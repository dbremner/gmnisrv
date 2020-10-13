#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "config.h"
#include "gemini.h"
#include "log.h"
#include "mime.h"
#include "server.h"
#include "url.h"

void
client_submit_response(struct gmnisrv_client *client,
	enum gemini_status status, const char *meta, FILE *body)
{
	client->status = status;
	client->meta = strdup(meta);
	client->body = body;
	client->pollfd->events = POLLOUT;
}

void
client_oom(struct gmnisrv_client *client)
{
	const char *error = "Out of memory";
	client_submit_response(client,
		GEMINI_STATUS_TEMPORARY_FAILURE, error, NULL);
}

static int
namecmp(const void *p1, const void *p2)
{
	return strcmp(*(char *const *)p1, *(char *const *)p2);
}

void
serve_autoindex(struct gmnisrv_client *client, const char *path)
{
	size_t bufsz = 0;
	size_t nameln = 0, namesz = 1024;
	char **names = calloc(namesz, sizeof(char *));

	DIR *dirp = opendir(path);
	if (!dirp) {
		goto internal_error;
	}

	bufsz += snprintf(NULL, 0, "# Index of %s\n\n", client->path);

	struct dirent *ent;
	errno = 0;
	while ((ent = readdir(dirp)) != NULL) {
		char fpath[PATH_MAX + 1];
		snprintf(fpath, sizeof(fpath), "%s/%s", path, ent->d_name);

		struct stat st;
		if (stat(fpath, &st) != 0) {
			goto internal_error;
		}

		if ((S_ISREG(st.st_mode) || S_ISLNK(st.st_mode) || S_ISDIR(st.st_mode))
				&& ent->d_name[0] != '.') {
			if (nameln >= namesz) {
				char **new = realloc(names, namesz * 2);
				if (!new) {
					goto internal_error;
				}
				namesz *= 2;
				names = new;
			}
			names[nameln++] = strdup(ent->d_name);
			bufsz += snprintf(NULL, 0, "=> %s\n", ent->d_name);
		}

		errno = 0;
	}
	if (errno != 0) {
		goto internal_error;
	}

	qsort(names, nameln, sizeof(names[0]), namecmp);

	FILE *buf = fmemopen(NULL, bufsz, "w+");
	if (!buf) {
		goto internal_error;
	}
	int r;
	r = fprintf(buf, "# Index of %s\n\n", client->path);
	assert(r > 0);
	for (size_t i = 0; i < nameln; ++i) {
		r = fprintf(buf, "=> %s\n", names[i]);
		assert(r > 0);
	}
	r = fseek(buf, 0, SEEK_SET);
	assert(r == 0);
	client_submit_response(client, GEMINI_STATUS_SUCCESS,
		"text/gemini", buf);

exit:
	closedir(dirp);
	for (size_t i = 0; i < nameln; ++i) {
		free(names[i]);
	}
	free(names);
	return;

internal_error:
	server_error("Error reading %s: %s", path, strerror(errno));
	client_submit_response(client, GEMINI_STATUS_PERMANENT_FAILURE,
		"Internal server error", NULL);
	goto exit;
}

void
serve_request(struct gmnisrv_client *client)
{
	struct gmnisrv_host *host = client->host;
	assert(host);
	assert(host->root); // TODO: reverse proxy support

	char path[PATH_MAX + 1];
	int n = snprintf(path, sizeof(path), "%s%s", host->root, client->path);
	if ((size_t)n >= sizeof(path)) {
		client_submit_response(client, GEMINI_STATUS_PERMANENT_FAILURE,
			"Request path exceeds PATH_MAX", NULL);
		return;
	}

	int nlinks = 0;
	struct stat st;
	while (true) {
		if ((n = stat(path, &st)) != 0) {
			client_submit_response(client,
				GEMINI_STATUS_NOT_FOUND, "Not found", NULL);
			return;
		}

		if (S_ISDIR(st.st_mode)) {
			if (host->autoindex) {
				serve_autoindex(client, path);
				return;
			} else {
				strncat(path,
					host->index ? host->index : "index.gmi",
					sizeof(path) - 1);
			}
		} else if (S_ISLNK(st.st_mode)) {
			++nlinks;
			if (nlinks > 3) {
				server_error("Maximum redirects exceeded for %s",
					client->path);
				client_submit_response(client,
					GEMINI_STATUS_NOT_FOUND,
					"Not found", NULL);
				return;
			}
			char path2[PATH_MAX + 1];
			ssize_t s = readlink(path, path2, sizeof(path2));
			assert(s != -1);
			strcpy(path, path2);
		} else if (S_ISREG(st.st_mode)) {
			break;
		} else {
			// Don't serve special files
			client_submit_response(client,
				GEMINI_STATUS_NOT_FOUND, "Not found", NULL);
			return;
		}
	}

	FILE *body = fopen(path, "r");
	if (!body) {
		if (errno == ENOENT) {
			client_submit_response(client,
				GEMINI_STATUS_NOT_FOUND, "Not found", NULL);
			return;
		} else {
			client_error(&client->addr, "error opening %s: %s",
					path, strerror(errno));
			client_submit_response(client, GEMINI_STATUS_PERMANENT_FAILURE,
				"Internal server error", NULL);
			return;
		}
	}

	const char *meta = gmnisrv_mimetype_for_path(path);
	client_submit_response(client, GEMINI_STATUS_SUCCESS, meta, body);
}

bool
request_validate(struct gmnisrv_client *client, char **path)
{
	struct Curl_URL *url = curl_url();
	if (!url) {
		client_oom(client);
		return false;
	}
	if (curl_url_set(url, CURLUPART_URL, client->buf, 0) != CURLUE_OK) {
		const char *error = "Protocol error: invalid URL";
		client_submit_response(client,
			GEMINI_STATUS_BAD_REQUEST, error, NULL);
		goto exit;
	}

	char *part;
	if (curl_url_get(url, CURLUPART_SCHEME, &part, 0) != CURLUE_OK) {
		const char *error = "Protocol error: invalid URL (expected scheme)";
		client_submit_response(client,
			GEMINI_STATUS_BAD_REQUEST, error, NULL);
		goto exit;
	} else if (strcmp(part, "gemini") != 0) {
		free(part);
		const char *error = "Refusing proxy to non-gemini URL";
		client_submit_response(client,
			GEMINI_STATUS_PROXY_REQUEST_REFUSED, error, NULL);
		goto exit;
	}
	free(part);

	if (curl_url_get(url, CURLUPART_HOST, &part, 0) != CURLUE_OK) {
		const char *error = "Protocol error: invalid URL (expected host)";
		client_submit_response(client,
			GEMINI_STATUS_BAD_REQUEST, error, NULL);
		goto exit;
	} else if (strcmp(part, client->host->hostname) != 0) {
		free(part);
		const char *error = "Protocol error: hostname does not match SNI";
		client_submit_response(client,
			GEMINI_STATUS_BAD_REQUEST, error, NULL);
		goto exit;
	}
	free(part);

	if (curl_url_get(url, CURLUPART_PATH, &part, 0) != CURLUE_OK) {
		const char *error = "Protocol error: invalid URL (expected path)";
		client_submit_response(client,
			GEMINI_STATUS_BAD_REQUEST, error, NULL);
		goto exit;
	}
	// NOTE: curl_url_set(..., CURLUPART_URL, ..., 0) will consoldate .. and
	// . to prevent directory traversal without additional code.
	*path = part;

	curl_url_cleanup(url);
	return true;

exit:
	curl_url_cleanup(url);
	return false;
}
