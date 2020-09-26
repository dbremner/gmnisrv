#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"
#include "gemini.h"
#include "log.h"
#include "mime.h"
#include "server.h"
#include "url.h"

void
client_submit_response(struct gmnisrv_client *client,
	enum gemini_status status, const char *meta, int bodyfd)
{
	client->status = status;
	client->meta = strdup(meta);
	client->bodyfd = bodyfd;
	client->pollfd->events = POLLOUT;
}

void
client_oom(struct gmnisrv_client *client)
{
	const char *error = "Out of memory";
	client_submit_response(client,
		GEMINI_STATUS_TEMPORARY_FAILURE, error, -1);
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
			"Request path exceeds PATH_MAX", -1);
		return;
	}

	if (path[strlen(path) - 1] == '/') {
		// TODO: Let user configure index file name?
		strncat(path, "index.gmi", sizeof(path) - 1);
	}

	int fd = open(path, O_RDONLY);
	if (fd == -1) {
		if (errno == ENOENT) {
			client_submit_response(client, GEMINI_STATUS_NOT_FOUND,
				"Not found", -1);
			return;
		} else {
			client_error(&client->addr, "error opening %s: %s",
					path, strerror(errno));
			client_submit_response(client, GEMINI_STATUS_PERMANENT_FAILURE,
				"Internal server error", -1);
			return;
		}
	}

	const char *meta = gmnisrv_mimetype_for_path(path);
	client_submit_response(client, GEMINI_STATUS_SUCCESS, meta, fd);
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
			GEMINI_STATUS_BAD_REQUEST, error, -1);
		goto exit;
	}

	char *part;
	if (curl_url_get(url, CURLUPART_SCHEME, &part, 0) != CURLUE_OK) {
		const char *error = "Protocol error: invalid URL (expected scheme)";
		client_submit_response(client,
			GEMINI_STATUS_BAD_REQUEST, error, -1);
		goto exit;
	} else if (strcmp(part, "gemini") != 0) {
		free(part);
		const char *error = "Refusing proxy to non-gemini URL";
		client_submit_response(client,
			GEMINI_STATUS_PROXY_REQUEST_REFUSED, error, -1);
		goto exit;
	}
	free(part);

	if (curl_url_get(url, CURLUPART_HOST, &part, 0) != CURLUE_OK) {
		const char *error = "Protocol error: invalid URL (expected host)";
		client_submit_response(client,
			GEMINI_STATUS_BAD_REQUEST, error, -1);
		goto exit;
	} else if (strcmp(part, client->host->hostname) != 0) {
		free(part);
		const char *error = "Protocol error: hostname does not match SNI";
		client_submit_response(client,
			GEMINI_STATUS_BAD_REQUEST, error, -1);
		goto exit;
	}
	free(part);

	if (curl_url_get(url, CURLUPART_PATH, &part, 0) != CURLUE_OK) {
		const char *error = "Protocol error: invalid URL (expected path)";
		client_submit_response(client,
			GEMINI_STATUS_BAD_REQUEST, error, -1);
		goto exit;
	}
	// NOTE: curl_url_set(..., CURLUPART_URL, ..., 0) will consoldate .. and
	// . to prevent directory traversal without additional code.
	*path = part;

exit:
	curl_url_cleanup(url);
	return true;
}
