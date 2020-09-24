#ifndef GMNISRV_CONFIG
#define GMNISRV_CONFIG
#include <arpa/inet.h>
#include <openssl/x509.h>

struct gmnisrv_tls {
	char *store;
	char *organization;
	char *email;
	SSL_CTX *ssl_ctx;
};

struct gmnisrv_host {
	char *hostname;
	char *root;
	X509 *x509;
	EVP_PKEY *pkey;
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
