#include <assert.h>
#include <errno.h>
#include <libgen.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "util.h"
#include <stdio.h>

static void
posix_dirname(char *path, char *dname)
{
	char p[PATH_MAX+1];
	char *t;

	assert(strlen(path) <= PATH_MAX);

	strcpy(p, path);
	t = dirname(path);
	memmove(dname, t, strlen(t) + 1);

	/* restore the path if dirname worked in-place */
	if (t == path && path != dname) {
		strcpy(path, p);
	}
}

/** Make directory and all of its parents */
int
mkdirs(char *path, mode_t mode)
{
	if (strcmp(path, "/") == 0 || strcmp(path, ".") == 0) {
		return 0;
	}
	char dname[PATH_MAX + 1];
	posix_dirname(path, dname);
	if (mkdirs(dname, mode) != 0) {
		return -1;
	}
	if (mkdir(path, mode) != 0 && errno != EEXIST) {
		return -1;
	}
	errno = 0;
	return 0;
}
