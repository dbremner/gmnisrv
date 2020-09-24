#include <arpa/inet.h>
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/socket.h>
#include "log.h"

static void
server_logf(FILE *f, const char *fmt, va_list ap)
{
	fprintf(f, "[gmnisrv] ");
	vfprintf(f, fmt, ap);
	fprintf(f, "\n");
}

static void
client_logf(FILE *f, struct sockaddr *addr, const char *fmt, va_list ap)
{
	char abuf[INET6_ADDRSTRLEN + 1];
	const char *addrs = inet_ntop(addr->sa_family,
		addr->sa_data, abuf, sizeof(abuf));
	assert(addrs);

	fprintf(f, "%s ", addrs);
	vfprintf(f, fmt, ap);
	fprintf(f, "\n");
}

void
server_log(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	server_logf(stdout, fmt, ap);
	va_end(ap);
}

void
client_log(struct sockaddr *addr, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	client_logf(stdout, addr, fmt, ap);
	va_end(ap);
}

void
server_error(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	server_logf(stderr, fmt, ap);
	va_end(ap);
}

void
client_error(struct sockaddr *addr, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	client_logf(stderr, addr, fmt, ap);
	va_end(ap);
}
