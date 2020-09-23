#ifndef GMNISRV_LOG
#define GMNISRV_LOG
#include <sys/socket.h>

void server_log(const char *fmt, ...);
void client_log(struct sockaddr *addr, const char *fmt, ...);
void server_error(const char *fmt, ...);
void client_error(struct sockaddr *addr, const char *fmt, ...);

#endif
