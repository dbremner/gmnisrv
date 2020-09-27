#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
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
		static const int t = 1;
		setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &t, sizeof(t));

		struct sockaddr_in in = {0};
		struct sockaddr_in6 in6 = {0};
		struct sockaddr *addr;
		size_t addrsz;
		if (b->family == AF_INET) {
			in.sin_family = AF_INET;
			in.sin_port = htons(b->port);
			memcpy(&in.sin_addr, b->addr, sizeof(struct in_addr));
			addr = (struct sockaddr *)&in;
			addrsz = sizeof(in);
		} else if (b->family == AF_INET6) {
			in6.sin6_family = AF_INET6;
			in6.sin6_port = htons(b->port);
			memcpy(&in6.sin6_addr, b->addr, sizeof(struct in6_addr));
			addr = (struct sockaddr *)&in6;
			addrsz = sizeof(in6);
#ifdef IPV6_V6ONLY
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

void
disconnect_client(struct gmnisrv_server *server, struct gmnisrv_client *client)
{
	if (client->status != GEMINI_STATUS_NONE) {
		struct timespec now, diff;
		clock_gettime(CLOCK_MONOTONIC, &now);
		timespec_diff(&client->ctime, &now, &diff);
		int ms = diff.tv_sec * 1000 + (int)(diff.tv_nsec / 1.0e6);
		client_log(&client->addr, "%s %s %3dms %5d %02d %s",
			client->host ? client->host->hostname : "(none)",
			client->path ? client->path : "(none)",
			ms, client->bbytes, (int)client->status, client->meta);
	}
	if (client->bio) {
		BIO_free_all(client->bio);
	}
	if (client->ssl) {
		SSL_free(client->ssl);
	}
	if (client->body) {
		fclose(client->body);
	}
	close(client->sockfd);
	free(client->meta);
	free(client->path);

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
	client->ssl = tls_get_ssl(server->conf, client->sockfd);
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

enum client_state {
	CLIENT_CONNECTED,
	CLIENT_DISCONNECTED,
};

static enum client_state
client_readable(struct gmnisrv_server *server, struct gmnisrv_client *client)
{
	if (!client->ssl && client_init_ssl(server, client) != 0) {
		return CLIENT_DISCONNECTED;
	}
	if (!client->host) {
		const char *error = "This server requires clients to support the TLS SNI (server name identification) extension";
		client_submit_response(client,
			GEMINI_STATUS_BAD_REQUEST, error, NULL);
		return CLIENT_CONNECTED;
	}

	int r = BIO_gets(client->bio, client->buf, sizeof(client->buf));
	if (r <= 0) {
		r = SSL_get_error(client->ssl, r);
		if (r == SSL_ERROR_WANT_READ) {
			return CLIENT_CONNECTED;
		}
		client_error(&client->addr, "SSL read error %s, disconnecting",
				ERR_error_string(r, NULL));
		disconnect_client(server, client);
		return CLIENT_DISCONNECTED;
	}
	client->buf[r] = '\0';

	char *newline = strstr(client->buf, "\r\n");
	if (!newline) {
		const char *error = "Protocol error: malformed request";
		client_submit_response(client,
			GEMINI_STATUS_BAD_REQUEST, error, NULL);
		return CLIENT_CONNECTED;
	}
	*newline = 0;

	if (!request_validate(client, &client->path)) {
		return CLIENT_CONNECTED;
	}

	serve_request(client);
	return CLIENT_CONNECTED;
}

static enum client_state
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
				return CLIENT_CONNECTED;
			}
			client->status = GEMINI_STATUS_NONE;
			client_error(&client->addr,
				"header write error %s, disconnecting",
				ERR_error_string(r, NULL));
			disconnect_client(server, client);
			return CLIENT_DISCONNECTED;
		}
		client->bufix += r;
		if (client->bufix >= client->bufln) {
			if (!client->body) {
				disconnect_client(server, client);
				return CLIENT_DISCONNECTED;
			} else {
				client->state = RESPOND_BODY;
				client->bufix = client->bufln = 0;
				return CLIENT_CONNECTED;
			}
		}
		break;
	case RESPOND_BODY:
		if (client->bufix >= client->bufln) {
			n = fread(client->buf, 1, sizeof(client->buf),
				client->body);
			if (n == -1) {
				client_error(&client->addr,
					"Error reading response body: %s",
					strerror(errno));
				disconnect_client(server, client);
				return CLIENT_DISCONNECTED;
			}
			if (n == 0) {
				// EOF
				disconnect_client(server, client);
				return CLIENT_DISCONNECTED;
			}
			client->bbytes += n;
			client->bufln = n;
			client->bufix = 0;
		}
		r = BIO_write(client->sbio, &client->buf[client->bufix],
			client->bufln - client->bufix);
		if (r <= 0) {
			r = SSL_get_error(client->ssl, r);
			if (r == SSL_ERROR_WANT_WRITE) {
				return CLIENT_CONNECTED;
			}
			client->status = GEMINI_STATUS_NONE;
			client_error(&client->addr, "body write error %s, disconnecting",
					ERR_error_string(r, NULL));
			disconnect_client(server, client);
			return CLIENT_DISCONNECTED;
		}
		client->bufix += r;
		break;
	}
	return false;
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
	if (!hostname) {
		return SSL_TLSEXT_ERR_NOACK;
	}

	struct gmnisrv_host *host = gmnisrv_config_get_host(
		server->conf, hostname);
	if (!host) {
		return SSL_TLSEXT_ERR_NOACK;
	}

	client->host = host;
	tls_set_host(client->ssl, client->host);
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
			int pi = i + server->nlisten;
			enum client_state s = CLIENT_CONNECTED;
			if ((server->fds[pi].revents & (POLLHUP | POLLERR))) {
				disconnect_client(server, &server->clients[i]);
				s = CLIENT_DISCONNECTED;
			}
			if (s == CLIENT_CONNECTED && (server->fds[pi].revents & POLLIN)) {
				s = client_readable(server, &server->clients[i]);
			}
			if (s == CLIENT_CONNECTED && (server->fds[pi].revents & POLLOUT)) {
				s = client_writable(server, &server->clients[i]);
			}
			if (s == CLIENT_DISCONNECTED) {
				--i;
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
	while (server->nclients) {
		disconnect_client(server, &server->clients[0]);
	}
	for (size_t i = 0; i < server->nfds; ++i) {
		close(server->fds[i].fd);
	}
	free(server->fds);
	free(server->clients);
}
