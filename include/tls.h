#ifndef GMNISRV_TLS
#define GMNISRV_TLS

struct gmnisrv_config;

int gmnisrv_tls_init(struct gmnisrv_config *conf);
SSL *gmnisrv_tls_get_ssl(struct gmnisrv_config *conf, int fd);
void gmnisrv_tls_set_host(SSL *ssl, struct gmnisrv_host *host);

#endif
