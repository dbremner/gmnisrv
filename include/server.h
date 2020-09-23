#ifndef GMNISRV_SERVER
#define GMNISRV_SERVER
#include <poll.h>
#include <stdbool.h>

#define GEMINI_MAX_URL 1024

struct gmnisrv_client {
	struct sockaddr addr;
	socklen_t addrlen;

	char buf[GEMINI_MAX_URL + 2];
	size_t bufln;

	int sockfd;
};

struct gmisrv_config;

struct gmnisrv_server {
	struct gmnisrv_config *conf;
	struct pollfd *fds;
	nfds_t nfds, fdsz;

	// nlisten is initialized once and does not change. The fds list starts
	// with this many listening sockets, then has sockets for each active
	// client, up to nfds.
	size_t nlisten;

	struct gmnisrv_client *clients;
	size_t nclients, clientsz;

	bool run;
};

int server_init(struct gmnisrv_server *server, struct gmnisrv_config *conf);
void server_run(struct gmnisrv_server *server);
void server_finish(struct gmnisrv_server *server);

#endif
