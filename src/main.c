#include <getopt.h>
#include <stdio.h>
#include "config.h"

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
		return r;
	}

	return 0;
}
