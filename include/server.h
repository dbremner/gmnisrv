#ifndef GMNISRV_SERVER
#define GMNISRV_SERVER
#include <poll.h>

#define GEMINI_MAX_URL 1024

struct gmnisrv_client {
	char buf[GEMINI_MAX_URL + 2];
	size_t bufln;
	int sockfd;
	int respfd;
};

struct gmisrv_config;

struct gmnisrv_server {
	struct gmnisrv_config *conf;
	struct pollfd *fds;
	nfds_t nfds, fdsz;

	size_t nlisten;

	struct gmnisrv_client *clients;
	size_t nclients, clientsz;
};

int server_init(struct gmnisrv_server *server, struct gmnisrv_config *conf);
void server_run(struct gmnisrv_server *server);
void server_finish(struct gmnisrv_server *server);

#endif
