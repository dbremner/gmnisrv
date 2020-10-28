#include <getopt.h>
#include <stdio.h>
#include "config.h"
#include "log.h"
#include "mime.h"
#include "server.h"
#include "tls.h"

static void
usage(const char *argv_0)
{
	fprintf(stderr, "Usage: %s [-C path]\n", argv_0);
}

int
main(int argc, char **argv)
{
	struct gmnisrv_config conf = {0};

	char *confpath = SYSCONFDIR "/gmnisrv.ini";
	int c;
	while ((c = getopt(argc, argv, "C:h")) != -1) {
		switch (c) {
		case 'C':
			confpath = optarg;
			break;
		case 'h':
			usage(argv[0]);
			return 0;
		default:
			fprintf(stderr, "Unknown flag %c\n", c);
			usage(argv[0]);
			return 1;
		}
	}
	if (optind < argc) {
		usage(argv[0]);
		return 1;
	}

	mime_init();

	int r = load_config(&conf, confpath);
	if (r != 0) {
		server_error("Config load failed");
		goto exit;
	}

	r = tls_init(&conf);
	if (r != 0) {
		server_error("TLS initialization failed");
		goto exit_conf;
	}

	struct gmnisrv_server server = {0};
	r = server_init(&server, &conf);
	if (r != 0) {
		goto exit_tls;
	}
	server_run(&server);

	server_finish(&server);
exit_tls:
	tls_finish(&conf);
exit_conf:
	config_finish(&conf);
exit:
	mime_finish();
	return 0;
}
