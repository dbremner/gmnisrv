#ifndef GMNISRV_CONFIG
#define GMNISRV_CONFIG
#include <arpa/inet.h>

struct gmnisrv_tls {
	char *store;
	char *organization;
	char *email;
};

struct gmnisrv_host {
	char *hostname;
	char *root;
	struct gmnisrv_host *next;
};

struct gmnisrv_bind {
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

struct gmnisrv_host *gmnisrv_config_get_host(
		struct gmnisrv_config *conf, const char *hostname);

#endif
