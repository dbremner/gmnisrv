#ifndef GMNISRV_CONFIG
#define GMNISRV_CONFIG
#include <arpa/inet.h>
#include <openssl/x509.h>
#include <stdbool.h>
#include "regexp.h"

struct gmnisrv_tls {
	char *store;
	char *organization;
	SSL_CTX *ssl_ctx;
};

enum gmnisrv_routing {
	ROUTE_PATH,
	ROUTE_REGEX,
};

struct gmnisrv_route {
	enum gmnisrv_routing routing;
	char *spec;
	union {
		char *path;
		uint8_t *regex;
	};

	char *root;
	char *index;
	char *rewrite;
	bool autoindex;
	bool cgi;

	struct gmnisrv_route *next;
};

struct gmnisrv_host {
	char *hostname;
	X509 *x509;
	EVP_PKEY *pkey;

	struct gmnisrv_route *routes;

	struct gmnisrv_host *next;
};

struct gmnisrv_bind {
	char *name;
	int family, port;
	char addr[sizeof(struct in6_addr)];
	struct gmnisrv_bind *next;
};

struct gmnisrv_config {
	struct gmnisrv_tls tls;
	struct gmnisrv_host *hosts;
	struct gmnisrv_bind *binds;
};

int load_config(struct gmnisrv_config *conf, const char *path);
void config_finish(struct gmnisrv_config *conf);

struct gmnisrv_host *gmnisrv_config_get_host(
	struct gmnisrv_config *conf, const char *hostname);

#endif
