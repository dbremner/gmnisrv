#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mime.h"

struct mime_info {
	char *mimetype;
	char *extension;
};

size_t mimedb_ln;
struct mime_info *mimedb;

static int
mimedb_compar(const void *va, const void *vb)
{
	const struct mime_info *a = va;
	const struct mime_info *b = vb;
	return strcmp(a->extension, b->extension);
}

void
mime_init()
{
	size_t mimedb_sz = 4096;
	mimedb = malloc(mimedb_sz * sizeof(struct mime_info));

	FILE *f = fopen(MIMEDB, "r");
	if (!f) {
		fprintf(stderr, "Unable to open MIME database for reading: %s\n",
			strerror(errno));
		fprintf(stderr, "Is " MIMEDB " installed?\n");
		assert(0);
	}

	char *line = NULL;
	size_t n = 0;
	while (getline(&line, &n, f) != -1) {
		if (line[0] == '#') {
			continue;
		}
		size_t l = strlen(line);
		if (l > 1 && line[l - 1] == '\n') {
			line[l - 1] = '\0';
		}

		if (mimedb_ln >= mimedb_sz) {
			mimedb_sz *= 2;
			struct mime_info *new = realloc(mimedb,
					mimedb_sz * sizeof(struct mime_info));
			assert(new);
			mimedb = new;
		}

		char *mime = strdup(strtok(line, " \t"));
		char *ext = strtok(NULL, " \t");
		if (!ext) {
			free(mime);
			continue;
		}

		do {
			mimedb[mimedb_ln].mimetype = strdup(mime);
			mimedb[mimedb_ln].extension = strdup(ext);
			++mimedb_ln;
		} while ((ext = strtok(NULL, " \t")));

		free(mime);
	}

	qsort(mimedb, mimedb_ln, sizeof(mimedb[0]), mimedb_compar);
}

void
mime_finish()
{
	for (size_t i = 0; i < mimedb_ln; ++i) {
		free(mimedb[i].mimetype);
		free(mimedb[i].extension);
	}
	free(mimedb);
}

static bool
has_suffix(const char *str, const char *suff)
{
	size_t a = strlen(str), b = strlen(suff);
	if (a < b) {
		return false;
	}
	return strncmp(&str[a - b], suff, b) == 0;
}

static int
path_compar(const void *va, const void *vb)
{
	char *ext = (char *)va;
	struct mime_info *mime = (struct mime_info *)vb;
	return strcmp(ext, mime->extension);
}

const char *
mimetype_for_path(const char *path)
{
	if (has_suffix(path, ".gmi") || has_suffix(path, ".gemini")) {
		return "text/gemini";
	}

	char *ext = strrchr(path, '.');
	if (!ext || !ext[1]) {
		return "application/octet-stream";
	}
	++ext;

	struct mime_info *mime = bsearch(
		ext, mimedb, mimedb_ln, sizeof(mimedb[0]), path_compar);
	if (!mime) {
		return "application/octet-stream";
	}
	return mime->mimetype;
}
