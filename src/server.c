#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include "config.h"
#include "server.h"

int
server_init(struct gmnisrv_server *server, struct gmnisrv_config *conf)
{
	server->conf = conf;
	for (struct gmnisrv_bind *b = conf->binds; b; b = b->next) {
		++server->nlisten;
	}

	assert(server->nlisten < 1024);
	server->nfds = server->nlisten;
	server->fds = calloc(server->nfds, sizeof(struct pollfd));
	assert(server->fds);

	server->clientsz = 1024 - server->nlisten;
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

		server->fds[i].fd = sockfd;
		server->fds[i].events = POLLIN;
		++i;
	}

	return 0;
}

void
server_run(struct gmnisrv_server *server)
{
	// TODO
	(void)server;
}

void
server_finish(struct gmnisrv_server *server)
{
	// TODO
	(void)server;
}
