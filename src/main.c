#include <getopt.h>
#include <stdio.h>
#include "config.h"
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

	int r = load_config(&conf, confpath);
	if (r != 0) {
		goto exit_conf;
	}

	r = gmnisrv_tls_init(&conf);
	if (r != 0) {
		goto exit_conf;
	}

	struct gmnisrv_server server = {0};
	r = server_init(&server, &conf);
	if (r != 0) {
		goto exit;
	}
	server_run(&server);

exit:
	server_finish(&server);
exit_conf:
	config_finish(&conf);
	return 0;
}
