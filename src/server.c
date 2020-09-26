#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/err.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "config.h"
#include "gemini.h"
#include "log.h"
#include "server.h"
#include "tls.h"
#include "url.h"

int
server_init(struct gmnisrv_server *server, struct gmnisrv_config *conf)
{
	server->conf = conf;
	for (struct gmnisrv_bind *b = conf->binds; b; b = b->next) {
		++server->nlisten;
	}

	assert(server->nlisten < 1024);
	server->nfds = server->nlisten;
	server->fds = calloc(1024, sizeof(struct pollfd));
	server->fdsz = 1024;
	assert(server->fds);

	server->clientsz = 1024;
	server->clients = calloc(server->clientsz, sizeof(struct gmnisrv_client));

	size_t i = 0;
	for (struct gmnisrv_bind *b = conf->binds; b; b = b->next) {
		int sockfd = socket(b->family, SOCK_STREAM, 0);
		if (sockfd < 0) {
			fprintf(stderr,
				"Failed to establish socket %s: %s\n",
				b->name, strerror(errno));
			return 1;
		}

		struct sockaddr *addr;
		size_t addrsz;
		if (b->family == AF_INET) {
			struct sockaddr_in in = {0};
			in.sin_family = AF_INET;
			memcpy(&in.sin_addr, b->addr, sizeof(b->addr));
			in.sin_port = htons(b->port);
			addr = (struct sockaddr *)&in;
			addrsz = sizeof(in);
		} else if (b->family == AF_INET6) {
			struct sockaddr_in6 in = {0};
			in.sin6_family = AF_INET6;
			memcpy(&in.sin6_addr, b->addr, sizeof(b->addr));
			in.sin6_port = htons(b->port);
			addr = (struct sockaddr *)&in;
			addrsz = sizeof(in);
#ifdef IPV6_V6ONLY
			static int t = 1;
			setsockopt(sockfd, IPPROTO_IPV6,
				IPV6_V6ONLY, &t, sizeof(t));
#endif
		} else {
			assert(0);
		}

		int r = bind(sockfd, addr, addrsz);
		if (r == -1) {
			fprintf(stderr,
				"Failed to bind socket %s: %s\n",
				b->name, strerror(errno));
			return 1;
		}

		r = listen(sockfd, 16);
		server_log("listening on %s", b->name);

		server->fds[i].fd = sockfd;
		server->fds[i].events = POLLIN;
		++i;
	}

	return 0;
}

static struct pollfd *
alloc_pollfd(struct gmnisrv_server *server)
{
	if (server->nfds >= server->fdsz) {
		size_t fdsz = server->fdsz * 2;
		struct pollfd *new = realloc(server->fds,
			fdsz * sizeof(struct pollfd));
		if (!new) {
			fprintf(stderr, "<serv>\tOut of file descriptors!\n");
			return NULL;
		}
		server->fds = new;
		server->fdsz = fdsz;
	}
	return &server->fds[server->nfds++];
}

static void
accept_client(struct gmnisrv_server *server, int fd)
{
	struct sockaddr addr;
	socklen_t addrlen = sizeof(addr);

	int sockfd = accept(fd, &addr, &addrlen);
	if (sockfd == -1) {
		server_error("accept error: %s", strerror(errno));
		return;
	}

	int flags = fcntl(fd, F_GETFL);
	int r = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
	if (r == -1) {
		close(sockfd);
		server_error("error setting O_NONBLOCK on client fd: %s", strerror(errno));
		return;
	}

	if (server->nclients >= server->clientsz) {
		size_t clientsz = server->clientsz * 2;
		struct gmnisrv_client *new = realloc(server->clients,
			clientsz * sizeof(struct gmnisrv_client));
		if (!new) {
			client_error(&addr, "disconnecting due to OOM condition");
			close(sockfd);
			return;
		}
		server->clients = new;
		server->clientsz = clientsz;
	}

	struct pollfd *pollfd = alloc_pollfd(server);
	if (pollfd == NULL) {
		client_error(&addr, "disconnecting due to OOM condition");
		close(sockfd);
		return;
	}

	struct gmnisrv_client *client = &server->clients[server->nclients++];
	memset(client, 0, sizeof(*client));
	client->sockfd = sockfd;
	client->pollfd = pollfd;
	client->addrlen = addrlen;
	client->server = server;
	clock_gettime(CLOCK_MONOTONIC, &client->ctime);
	memcpy(&client->addr, &addr, sizeof(addr));

	pollfd->fd = sockfd;
	pollfd->events = POLLIN;
}


static void
timespec_diff(struct timespec *start,
	struct timespec *stop, struct timespec *out)
{
    if ((stop->tv_nsec - start->tv_nsec) < 0) {
        out->tv_sec = stop->tv_sec - start->tv_sec - 1;
        out->tv_nsec = stop->tv_nsec - start->tv_nsec + 1000000000;
    } else {
        out->tv_sec = stop->tv_sec - start->tv_sec;
        out->tv_nsec = stop->tv_nsec - start->tv_nsec;
    }
}

static void
disconnect_client(struct gmnisrv_server *server, struct gmnisrv_client *client)
{
	if (client->status != GEMINI_STATUS_NONE) {
		struct timespec now, diff;
		clock_gettime(CLOCK_MONOTONIC, &now);
		timespec_diff(&client->ctime, &now, &diff);
		int ms = diff.tv_sec * 1000 + (int)(diff.tv_nsec / 1.0e6);
		client_log(&client->addr, "%dms %s %s %02d %s", ms,
			client->host ? client->host->hostname : "(none)",
			client->path ? client->path : "(none)",
			(int)client->status, client->meta);
	}
	close(client->sockfd);
	free(client->meta);
	// TODO: Close bios, body, etc

	size_t index = (client - server->clients) / sizeof(struct gmnisrv_client);
	memmove(client, &client[1], &server->clients[server->clientsz] - client);
	memmove(&server->fds[server->nlisten + index],
		&server->fds[server->nlisten + index + 1],
		server->fdsz - (server->nlisten + index + 1) * sizeof(struct pollfd));
	--server->nfds;
	--server->nclients;
}

static int
client_init_ssl(struct gmnisrv_server *server, struct gmnisrv_client *client)
{
	client->ssl = gmnisrv_tls_get_ssl(server->conf, client->sockfd);
	if (!client->ssl) {
		client_error(&client->addr,
			"unable to initialize SSL, disconnecting");
		disconnect_client(server, client);
		return 1;
	}

	int r = SSL_accept(client->ssl);
	if (r != 1) {
		r = SSL_get_error(client->ssl, r);
		if (r == SSL_ERROR_WANT_READ || r == SSL_ERROR_WANT_WRITE) {
			return 1;
		}
		client_error(&client->addr, "SSL accept error %s, disconnecting",
				ERR_error_string(r, NULL));
		disconnect_client(server, client);
		return 1;
	}

	client->sbio = BIO_new(BIO_f_ssl());
	BIO_set_ssl(client->sbio, client->ssl, 0);
	client->bio = BIO_new(BIO_f_buffer());
	BIO_push(client->bio, client->sbio);
	return 0;
}

static void
client_submit_response(struct gmnisrv_client *client,
	enum gemini_status status, const char *meta, int bodyfd)
{
	client->status = status;
	client->meta = strdup(meta);
	client->bodyfd = bodyfd;
	client->pollfd->events = POLLOUT;
}

static void
client_oom(struct gmnisrv_client *client)
{
	const char *error = "Out of memory";
	client_submit_response(client,
		GEMINI_STATUS_TEMPORARY_FAILURE, error, -1);
}

static bool
request_validate(struct gmnisrv_client *client, char **path)
{
	struct Curl_URL *url = curl_url();
	if (!url) {
		client_oom(client);
		return false;
	}
	if (curl_url_set(url, CURLUPART_URL, client->buf, 0) != CURLUE_OK) {
		const char *error = "Protocol error: invalid URL";
		client_submit_response(client,
			GEMINI_STATUS_BAD_REQUEST, error, -1);
		goto exit;
	}

	char *part;
	if (curl_url_get(url, CURLUPART_SCHEME, &part, 0) != CURLUE_OK) {
		const char *error = "Protocol error: invalid URL (expected scheme)";
		client_submit_response(client,
			GEMINI_STATUS_BAD_REQUEST, error, -1);
		goto exit;
	} else if (strcmp(part, "gemini") != 0) {
		free(part);
		const char *error = "Refusing proxy to non-gemini URL";
		client_submit_response(client,
			GEMINI_STATUS_PROXY_REQUEST_REFUSED, error, -1);
		goto exit;
	}
	free(part);

	if (curl_url_get(url, CURLUPART_HOST, &part, 0) != CURLUE_OK) {
		const char *error = "Protocol error: invalid URL (expected host)";
		client_submit_response(client,
			GEMINI_STATUS_BAD_REQUEST, error, -1);
		goto exit;
	} else if (strcmp(part, client->host->hostname) != 0) {
		free(part);
		const char *error = "Protocol error: hostname does not match SNI";
		client_submit_response(client,
			GEMINI_STATUS_BAD_REQUEST, error, -1);
		goto exit;
	}
	free(part);

	if (curl_url_get(url, CURLUPART_PATH, &part, 0) != CURLUE_OK) {
		const char *error = "Protocol error: invalid URL (expected path)";
		client_submit_response(client,
			GEMINI_STATUS_BAD_REQUEST, error, -1);
		goto exit;
	}
	// NOTE: curl_url_set(..., CURLUPART_URL, ..., 0) will consoldate .. and
	// . to prevent directory traversal without additional code.
	*path = part;

exit:
	curl_url_cleanup(url);
	return true;
}

static void
client_readable(struct gmnisrv_server *server, struct gmnisrv_client *client)
{
	if (!client->ssl && client_init_ssl(server, client) != 0) {
		return;
	}
	if (!client->host) {
		const char *error = "This server requires clients to support the TLS SNI (server name identification) extension";
		client_submit_response(client,
			GEMINI_STATUS_BAD_REQUEST, error, -1);
		return;
	}

	// XXX: Can buf be statically allocated?
	int r = BIO_gets(client->bio, client->buf, sizeof(client->buf));
	if (r <= 0) {
		r = SSL_get_error(client->ssl, r);
		if (r == SSL_ERROR_WANT_READ) {
			return;
		}
		client_error(&client->addr, "SSL read error %s, disconnecting",
				ERR_error_string(r, NULL));
		disconnect_client(server, client);
		return;
	}
	client->buf[r] = '\0';

	char *newline = strstr(client->buf, "\r\n");
	if (!newline) {
		const char *error = "Protocol error: malformed request";
		client_submit_response(client,
			GEMINI_STATUS_BAD_REQUEST, error, -1);
		return;
	}
	*newline = 0;

	if (!request_validate(client, &client->path)) {
		return;
	}

	// TODO: prep response
	const char *error = "TODO: Finish implementation";
	client_submit_response(client,
		GEMINI_STATUS_TEMPORARY_FAILURE, error, -1);
}

static void
client_writable(struct gmnisrv_server *server, struct gmnisrv_client *client)
{
	int r;
	ssize_t n;
	switch (client->state) {
	case RESPOND_HEADER:
		if (client->bufix == 0) {
			assert(strlen(client->meta) <= 1024);
			n = snprintf(client->buf, sizeof(client->buf),
				"%02d %s\r\n", (int)client->status,
				client->meta);
			assert(n > 0);
			client->bufln = n;
		}
		r = BIO_write(client->sbio, &client->buf[client->bufix],
			client->bufln - client->bufix);
		if (r <= 0) {
			r = SSL_get_error(client->ssl, r);
			if (r == SSL_ERROR_WANT_WRITE) {
				return;
			}
			client->status = GEMINI_STATUS_NONE;
			client_error(&client->addr, "SSL read error %s, disconnecting",
					ERR_error_string(r, NULL));
			disconnect_client(server, client);
			return;
		}
		client->bufix += r;
		if (client->bufix >= client->bufln) {
			// TODO: Start sending response body as well
			disconnect_client(server, client);
			return;
		}
		break;
	case RESPOND_BODY:
		assert(0);
		break;
	}

	(void)server;
}

static long
sni_callback(SSL *ssl, int *al, void *arg)
{
	(void)al;
	struct gmnisrv_server *server = (struct gmnisrv_server *)arg;
	struct gmnisrv_client *client;
	for (size_t i = 0; i < server->nclients; ++i) {
		client = &server->clients[i];
		if (client->ssl == ssl) {
			break;
		}
		client = NULL;
	}

	if (!client) {
		return SSL_TLSEXT_ERR_NOACK;
	}

	const char *hostname = SSL_get_servername(client->ssl,
		SSL_get_servername_type(client->ssl));
	struct gmnisrv_host *host = gmnisrv_config_get_host(
		server->conf, hostname);
	if (!host) {
		return SSL_TLSEXT_ERR_NOACK;
	}

	client->host = host;
	gmnisrv_tls_set_host(client->ssl, client->host);
	return SSL_TLSEXT_ERR_OK;
}

bool *run;

static void
handle_sigint(int s, siginfo_t *i, void *c)
{
	*run = false;
	(void)s; (void)i; (void)c;
}

void
server_run(struct gmnisrv_server *server)
{
	struct sigaction act = {
		.sa_sigaction = handle_sigint,
		.sa_flags = SA_SIGINFO,
	};
	struct sigaction oint, oterm;
	run = &server->run;
	int r = sigaction(SIGINT, &act, &oint);
	assert(r == 0);
	r = sigaction(SIGTERM, &act, &oterm);
	assert(r == 0);

	SSL_CTX_set_tlsext_servername_arg(server->conf->tls.ssl_ctx, server);
	SSL_CTX_set_tlsext_servername_callback(
		server->conf->tls.ssl_ctx, sni_callback);

	server_log("gmnisrv started");

	server->run = true;
	do {
		r = poll(server->fds, server->nfds, -1);
		if (r == -1 && (errno == EAGAIN || errno == EINTR)) {
			continue;
		} else if (r == -1) {
			break;
		}

		for (size_t i = 0; i < server->nlisten; ++i) {
			if ((server->fds[i].revents & POLLIN)) {
				accept_client(server, server->fds[i].fd);
			}
			if ((server->fds[i].revents & POLLERR)) {
				server_error("Error on listener poll");
				server->run = false;
			}
		}

		for (size_t i = 0; i < server->nclients; ++i) {
			if ((server->fds[server->nlisten + i].revents & (POLLHUP | POLLERR))) {
				disconnect_client(server, &server->clients[i]);
				--i;
				continue;
			}
			if ((server->fds[server->nlisten + i].revents & POLLIN)) {
				client_readable(server, &server->clients[i]);
			}
			if ((server->fds[server->nlisten + i].revents & POLLOUT)) {
				client_writable(server, &server->clients[i]);
			}
		}
	} while (server->run);

	server_log("gmnisrv terminating");

	r = sigaction(SIGINT, &oint, NULL);
	assert(r == 0);
	r = sigaction(SIGTERM, &oterm, NULL);
	assert(r == 0);
}

void
server_finish(struct gmnisrv_server *server)
{
	// TODO
	(void)server;
}
