#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include "config.h"
#include "ini.h"
#include "regex.h"

struct gmnisrv_host *
gmnisrv_config_get_host(struct gmnisrv_config *conf, const char *hostname)
{
	struct gmnisrv_host *host = conf->hosts;
	while (host) {
		if (strcmp(host->hostname, hostname) == 0) {
			return host;
		}
		host = host->next;
	}
	return NULL;
}

struct gmnisrv_route *
gmnisrv_host_get_route(struct gmnisrv_host *host,
		enum gmnisrv_routing routing, const char *spec)
{
	struct gmnisrv_route *route = host->routes;
	while (route) {
		if (route->routing == routing
				&& strcmp(route->spec, spec) == 0) {
			return route;
		}
		route = route->next;
	}
	return NULL;
}

static int
parse_listen(struct gmnisrv_config *conf, const char *value)
{
	char listen[4096];
	assert(strlen(value) < sizeof(listen) - 1);
	strcpy(listen, value);

	char *tok = strtok(listen, " ");
	while (tok) {
		char *port = tok;
		struct gmnisrv_bind *bind =
			calloc(1, sizeof(struct gmnisrv_bind));
		assert(bind);
		bind->port = 1965;
		bind->name = strdup(tok);

		if (tok[0] == '[') {
			bind->family = AF_INET6;
			char *e = strchr(tok, ']');
			if (!e) {
				fprintf(stderr,
					"Error: invalid address specification %s\n",
					tok);
				return 0;
			}
			*e = '\0';
			port = e + 1;
			++tok;
		} else {
			bind->family = AF_INET;
		}

		port = strchr(port, ':');
		if (port) {
			*port = '\0';
			++port;

			char *endptr;
			bind->port = strtoul(port, &endptr, 10);
			if (*endptr) {
				fprintf(stderr, "Error: invalid port %s\n", port);
				return 0;
			}
			if (bind->port == 0 || bind->port > 65535) {
				fprintf(stderr, "Error: invalid port %s\n", port);
				return 0;
			}
		}

		int r = inet_pton(bind->family, tok, bind->addr);
		if (r != 1) {
			fprintf(stderr,
				"Error: invalid address specification %s\n",
				tok);
			return 0;
		}

		bind->next = conf->binds;
		conf->binds = bind;
		tok = strtok(NULL, " ");
	}

	return 1;
}

static int
conf_ini_handler(void *user, const char *section,
	const char *name, const char *value)
{
	struct gmnisrv_config *conf = (struct gmnisrv_config *)user;
	struct {
		char *section;
		char *name;
		char **value;
	} strvars[] = {
		{ ":tls", "store", &conf->tls.store },
		{ ":tls", "organization", &conf->tls.organization },
	};
	struct {
		char *section;
		char *name;
		int (*fn)(struct gmnisrv_config *conf, const char *value);
	} fnvars[] = {
		{ "", "listen", &parse_listen, }
	};

	for (size_t i = 0; i < sizeof(strvars) / sizeof(strvars[0]); ++i) {
		if (strcmp(strvars[i].section, section) != 0) {
			continue;
		}
		if (strcmp(strvars[i].name, name) != 0) {
			continue;
		}
		*strvars[i].value = strdup(value);
		return 1;
	}

	for (size_t i = 0; i < sizeof(fnvars) / sizeof(fnvars[0]); ++i) {
		if (strcmp(fnvars[i].section, section) != 0) {
			continue;
		}
		if (strcmp(fnvars[i].name, name) != 0) {
			continue;
		}
		return fnvars[i].fn(conf, value);
	}

	if (section[0] == '\0' || section[0] == ':') {
		fprintf(stderr, "Unknown config option [%s]%s\n", section, name);
		return 0;
	}

	const char *spec;
	char hostname[1024 + 1];
	enum gmnisrv_routing routing;
	size_t hostln = strcspn(section, ":~");
	switch (section[hostln]) {
	case '\0':
		routing = ROUTE_PATH;
		spec = "/";
		break;
	case ':':
		routing = ROUTE_PATH;
		spec = &section[hostln + 1];
		break;
	case '~':
		routing = ROUTE_REGEX;
		spec = &section[hostln + 1];
		break;
	}
	assert(hostln < sizeof(hostname));
	strncpy(hostname, section, hostln);
	hostname[hostln] = '\0';

	struct gmnisrv_host *host = gmnisrv_config_get_host(conf, hostname);
	if (!host) {
		host = calloc(1, sizeof(struct gmnisrv_host));
		assert(host);
		host->hostname = strdup(section);
		host->next = conf->hosts;
		conf->hosts = host;
	}

	int bytecode_len;
	char error_msg[64];
	struct gmnisrv_route *route =
		gmnisrv_host_get_route(host, routing, spec);
	if (!route) {
		route = calloc(1, sizeof(struct gmnisrv_route));
		assert(route);
		route->spec = strdup(spec);
		route->routing = routing;
		route->next = host->routes;
		host->routes = route;

		switch (route->routing) {
		case ROUTE_PATH:
			route->path = strdup(spec);
			break;
		case ROUTE_REGEX:
			route->regex = lre_compile(&bytecode_len,
				error_msg, sizeof(error_msg),
				spec, strlen(spec), 0, NULL);
			if (!route->regex) {
				fprintf(stderr, "Error compiling regex '%s': %s\n",
					spec, error_msg);
				return 0;
			}
			break;
		}
	}

	struct {
		char *name;
		char **value;
	} route_strvars[] = {
		{ "root", &route->root },
		{ "index", &route->index },
	};
	struct {
		char *name;
		bool *value;
	} route_bvars[] = {
		{ "autoindex", &route->autoindex },
		{ "cgi", &route->cgi },
	};

	for (size_t i = 0; i < sizeof(route_strvars) / sizeof(route_strvars[0]); ++i) {
		if (strcmp(route_strvars[i].name, name) != 0) {
			continue;
		}
		*route_strvars[i].value = strdup(value);
		return 1;
	}

	for (size_t i = 0; i < sizeof(route_bvars) / sizeof(route_bvars[0]); ++i) {
		if (strcmp(route_bvars[i].name, name) != 0) {
			continue;
		}
		*route_bvars[i].value =
			strcasecmp(value, "yes") == 0 ||
			strcasecmp(value, "true") == 0 ||
			strcasecmp(value, "on") == 0;
		return 1;
	}

	fprintf(stderr, "Unknown config option [%s]%s\n", section, name);
	return 0;
}

static int
validate_config(struct gmnisrv_config *conf)
{
	if (!conf->binds) {
		fprintf(stderr, "Error: config missing listen directive\n");
		return 1;
	}
	if (!conf->hosts) {
		fprintf(stderr, "Error: config defines no hosts\n");
		return 1;
	}
	if (!conf->tls.store) {
		fprintf(stderr, "Error: config defines no certificate store\n");
		return 1;
	}
	return 0;
}

int
load_config(struct gmnisrv_config *conf, const char *path)
{
	FILE *f = fopen(path, "r");
	if (!f) {
		fprintf(stderr, "Error opening %s: %s\n",
				path, strerror(errno));
		return 1;
	}

	int n = ini_parse_file(f, conf_ini_handler, conf);
	fclose(f);
	if (n != 0) {
		fprintf(stderr, "at %s:%d\n", path, n);
		return 1;
	}

	return validate_config(conf);
}

void
config_finish(struct gmnisrv_config *conf)
{
	free(conf->tls.store);
	free(conf->tls.organization);
	struct gmnisrv_bind *bind = conf->binds;
	while (bind) {
		struct gmnisrv_bind *next = bind->next;
		free(bind->name);
		free(bind);
		bind = next;
	}

	struct gmnisrv_host *host = conf->hosts;
	while (host) {
		struct gmnisrv_host *next = host->next;
		free(host->hostname);

		struct gmnisrv_route *route = host->routes;
		while (route) {
			switch (route->routing) {
			case ROUTE_PATH:
				free(route->path);
				break;
			case ROUTE_REGEX:
				free(route->regex);
				break;
			}

			struct gmnisrv_route *rnext = route->next;
			free(route->spec);
			free(route->root);
			free(route->index);
			free(route);
			route = rnext;
		}

		free(host);
		host = next;
	}
}
