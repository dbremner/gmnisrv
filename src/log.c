#include <arpa/inet.h>
#include <assert.h>
#include <stdarg.h>
#include <string.h>
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

	switch(addr->sa_family) {
	case AF_INET: {
	  struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
	  const char* result = inet_ntop(AF_INET, &(addr_in->sin_addr), abuf, INET_ADDRSTRLEN);
	  assert(result);
	  break;
	}
	case AF_INET6: {
	  struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)addr;
	  const char* result = inet_ntop(AF_INET6, &(addr_in6->sin6_addr), abuf, INET6_ADDRSTRLEN);
	  assert(result);
	  break;
	}
	default:
	  strncpy(abuf, "Unknown AF", INET6_ADDRSTRLEN);
	  break;
	}

	fprintf(f, "%s ", abuf);
	vfprintf(f, fmt, ap);
	fprintf(f, "\n");
}

void
server_log(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	server_logf(stderr, fmt, ap);
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
