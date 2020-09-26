#include <stdbool.h>
#include <string.h>
#include "mime.h"

static bool
has_suffix(const char *str, const char *suff)
{
	size_t a = strlen(str), b = strlen(suff);
	if (a < b) {
		return false;
	}
	return strncmp(&str[a - b], suff, b) == 0;
}

const char *
gmnisrv_mimetype_for_path(const char *path)
{
	// TODO: Read /etc/mime.types
	// TODO: Consider adding content-disposition fields like filename
	if (has_suffix(path, ".gmi") || has_suffix(path, ".gemini")) {
		return "text/gemini";
	}
	if (has_suffix(path, ".txt")) {
		return "text/plain";
	}
	if (has_suffix(path, ".png")) {
		return "image/png";
	}
	return "application/octet-stream";
}
