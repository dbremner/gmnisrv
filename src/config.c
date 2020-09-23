#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"
#include "ini.h"

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

static int
parse_listen(struct gmnisrv_config *conf, const char *value)
{
	// TODO
	(void)conf;
	(void)value;
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
		{ ":tls", "email", &conf->tls.email },
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

	struct gmnisrv_host *host = gmnisrv_config_get_host(conf, section);
	if (!host) {
		host = calloc(1, sizeof(struct gmnisrv_host));
		host->hostname = strdup(section);
		host->next = conf->hosts;
		conf->hosts = host;
	}

	struct {
		char *name;
		char **value;
	} host_strvars[] = {
		{ "root", &host->root },
	};

	for (size_t i = 0; i < sizeof(host_strvars) / sizeof(host_strvars[0]); ++i) {
		if (strcmp(host_strvars[i].name, name) != 0) {
			continue;
		}
		*host_strvars[i].value = strdup(value);
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
