#ifndef GMNISRV_SERVER
#define GMNISRV_SERVER
#include <openssl/ssl.h>
#include <poll.h>
#include <time.h>
#include <stdbool.h>
#include "gemini.h"
#include "url.h"

struct gmnisrv_server;

enum response_state {
	RESPOND_HEADER,
	RESPOND_BODY,
};

struct gmnisrv_client {
	struct gmnisrv_server *server;
	struct timespec ctime;
	struct sockaddr addr;
	socklen_t addrlen;
	int sockfd;
	struct pollfd *pollfd;

	SSL *ssl;
	BIO *bio, *sbio;

	char buf[GEMINI_MAX_URL + 3];
	size_t bufix, bufln;

	enum response_state state;
	enum gemini_status status;
	char *meta;
	int bodyfd;
 
	struct gmnisrv_host *host;
	char *path;
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
