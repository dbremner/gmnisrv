#ifndef GMNISRV_SERVER
#define GMNISRV_SERVER
#include <assert.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <time.h>
#include <stdbool.h>
#include "gemini.h"
#include "url.h"

struct gmnisrv_server;

enum client_state {
	CLIENT_STATE_REQUEST,
	CLIENT_STATE_SSL,
	CLIENT_STATE_HEADER,
	CLIENT_STATE_BODY,
};

struct gmnisrv_client {
	struct gmnisrv_server *server;
	struct timespec ctime;
	struct sockaddr addr;
	socklen_t addrlen;
	int sockfd;
	struct pollfd *pollfd;

	SSL *ssl;
	BIO *rbio, *wbio;

	char buf[4096];
	size_t bufix, bufln;

	enum client_state state, next;
	enum gemini_status status;
	char *meta;
	FILE *body;
	size_t bbytes;
 
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

// server.c
int server_init(struct gmnisrv_server *server, struct gmnisrv_config *conf);
void server_run(struct gmnisrv_server *server);
void server_finish(struct gmnisrv_server *server);

void disconnect_client(struct gmnisrv_server *server,
		struct gmnisrv_client *client);

// serve.c
void serve_request(struct gmnisrv_client *client);
bool request_validate(struct gmnisrv_client *client, char **path);
void client_submit_response(struct gmnisrv_client *client,
	enum gemini_status status, const char *meta, FILE *body);
void client_oom(struct gmnisrv_client *client);

#endif
