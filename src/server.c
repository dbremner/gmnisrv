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
	client->sockfd = sockfd;
	client->addrlen = addrlen;
	memcpy(&client->addr, &addr, sizeof(addr));
	pollfd->fd = sockfd;
	pollfd->events = POLLIN;
}

static void
disconnect_client(struct gmnisrv_server *server, struct gmnisrv_client *client)
{
	close(client->sockfd);
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

	BIO *sbio = BIO_new(BIO_f_ssl());
	BIO_set_ssl(sbio, client->ssl, 0);
	client->bio = BIO_new(BIO_f_buffer());
	BIO_push(client->bio, sbio);
	return 0;
}

static void
client_readable(struct gmnisrv_server *server, struct gmnisrv_client *client)
{
	if (!client->ssl && client_init_ssl(server, client) != 0) {
		return;
	}

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

	if (!client->host) {
		// TODO: We can do a friendly disconnect at this point
		client_error(&client->addr,
			"client did not perform SNI, disconnecting");
		disconnect_client(server, client);
		return;
	}

	char *newline = strstr(client->buf, "\r\n");
	if (!newline) {
		// TODO: We can do a friendly disconnect at this point
		client_error(&client->addr, "protocol error, disconnecting");
		disconnect_client(server, client);
		return;
	}
	*newline = 0;

	client_log(&client->addr, "%s", client->buf);
}

static void
client_writable(struct gmnisrv_server *server, struct gmnisrv_client *client)
{
	// TODO
	(void)server;
	(void)client;
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
