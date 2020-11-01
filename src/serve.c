#include <arpa/inet.h>
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
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
	client->state = CLIENT_STATE_HEADER;
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

static void
serve_cgi(struct gmnisrv_client *client, const char *path,
		const char *script_name, const char *pathinfo)
{
	int pfd[2];
	if (pipe(pfd) == -1) {
		server_error("pipe: %s", strerror(errno));
		client_submit_response(client, GEMINI_STATUS_PERMANENT_FAILURE,
			"Internal server error", NULL);
		return;
	}

	pid_t pid = fork();
	if (pid == -1) {
		server_error("fork: %s", strerror(errno));
		client_submit_response(client, GEMINI_STATUS_PERMANENT_FAILURE,
			"Internal server error", NULL);
		close(pfd[0]);
		close(pfd[1]);
		return;
	} else if (pid == 0) {
		close(pfd[0]);
		dup2(pfd[1], STDOUT_FILENO);
		close(pfd[1]);

		// I don't feel like freeing this stuff and this process is
		// going to die soon anyway so let's just be hip and call it an
		// arena allocator :^)
		struct Curl_URL *url = curl_url();
		assert(url);
		CURLUcode uc = curl_url_set(url, CURLUPART_URL, client->buf, 0);
		assert(uc == CURLUE_OK);

		char *query;
		uc = curl_url_get(url, CURLUPART_QUERY, &query, CURLU_URLDECODE);
		if (uc != CURLUE_OK) {
			assert(uc == CURLUE_NO_QUERY);
		} else {
			setenv("QUERY_STRING", query, 1);
		}

		char abuf[INET6_ADDRSTRLEN + 1];
		const char *addrs = inet_ntop(client->addr.sa_family,
			client->addr.sa_data, abuf, sizeof(abuf));
		assert(addrs);

		// Compatible with Jetforce
		setenv("GATEWAY_INTERFACE", "GCI/1.1", 1);
		setenv("SERVER_PROTOCOL", "GEMINI", 1);
		setenv("SERVER_SOFTWARE", "gmnisrv/0.0.0", 1);
		setenv("GEMINI_URL", client->buf, 1);
		setenv("SCRIPT_NAME", script_name, 1);
		setenv("PATH_INFO", pathinfo, 1);
		setenv("SERVER_NAME", client->host->hostname, 1);
		setenv("HOSTNAME", client->host->hostname, 1);
		//setenv("SERVER_PORT", "", 1); // TODO
		setenv("REMOTE_HOST", addrs, 1);
		setenv("REMOTE_ADDR", addrs, 1);

		const SSL_CIPHER *cipher = SSL_get_current_cipher(client->ssl);
		setenv("TLS_CIPHER", SSL_CIPHER_get_name(cipher), 1);
		setenv("TLS_VERSION", SSL_CIPHER_get_version(cipher), 1);

		// TODO: Client certificate details

		execlp(path, path, NULL);
		server_error("execlp: %s", strerror(errno));
		_exit(1);
	} else {
		close(pfd[1]);
		FILE *f = fdopen(pfd[0], "r");
		client_submit_response(client, GEMINI_STATUS_SUCCESS, "(cgi)", f);
		client->state = CLIENT_STATE_BODY; // The CGI script sends meta
		client->bufix = client->bufln = 0;
	}
}

static bool
route_match(struct gmnisrv_route *route, const char *path, const char **revised)
{
	switch (route->routing) {
	case ROUTE_PATH:;
		size_t l = strlen(route->path);
		if (strncmp(path, route->path, l) != 0) {
			return false;
		}
		if (route->path[l-1] != '/' && path[l] != '\0' && path[l] != '/') {
			// Prevents path == "/foobar" from matching
			// route == "/foo":
			return false;
		}
		if (route->path[l-1] == '/') {
			*revised = &path[l-1];
		} else {
			*revised = &path[l];
		}
		return true;
	case ROUTE_REGEX:;
		int ncapture = lre_get_capture_count(route->regex);
		uint8_t **capture = NULL;
		if (ncapture > 0) {
			capture = malloc(sizeof(capture[0]) * ncapture * 2);
			assert(capture);
		}
		int r = lre_exec(capture, route->regex,
			(const uint8_t *)path, 0, strlen(path), 0, NULL);
		if (r != 1) {
			free(capture);
			return false;
		}
		// TODO: Process captures and rewrites
		*revised = path;
		return true;
	}

	assert(0); // Invariant
}

void
serve_request(struct gmnisrv_client *client)
{
	struct gmnisrv_host *host = client->host;
	assert(host);
	struct gmnisrv_route *route = host->routes;
	assert(route);

	const char *url_path;
	while (route) {
		if (route_match(route, client->path, &url_path)) {
			break;
		}

		route = route->next;
	}

	if (!route) {
		client_submit_response(client,
			GEMINI_STATUS_NOT_FOUND, "Not found", NULL);
		return;
	}

	assert(route->root); // TODO: reverse proxy support

	// Paths on paths on paths on paths
	// My apologies to the stack
	char client_path[PATH_MAX + 1] = "";
	char real_path[PATH_MAX + 1] = "";
	char pathinfo[PATH_MAX + 1] = "";
	char temp_path[PATH_MAX + 1] = "";
	int n = snprintf(real_path, sizeof(real_path), "%s%s", route->root, url_path);
	if ((size_t)n >= sizeof(real_path)) {
		client_submit_response(client, GEMINI_STATUS_PERMANENT_FAILURE,
			"Request path exceeds PATH_MAX", NULL);
		return;
	}
	strcpy(client_path, client->path);

	int nlinks = 0;
	struct stat st;
	while (true) {
		if ((n = stat(real_path, &st)) != 0) {
			if (route->cgi) {
				const char *new;
				strcpy(temp_path, client_path);
				new = basename((char *)temp_path);

				size_t l = strlen(new), q = strlen(pathinfo);
				memmove(&pathinfo[l + 1], pathinfo, q);
				pathinfo[0] = '/';
				memcpy(&pathinfo[1], new, l);

				strcpy(temp_path, client_path);
				new = dirname((char *)temp_path);
				strcpy(client_path, new);

				strcpy(temp_path, real_path);
				new = dirname((char *)temp_path);
				strcpy(real_path, new);

				if (route_match(route, client_path, &url_path)) {
					n = snprintf(real_path, sizeof(real_path),
						"%s%s", route->root, url_path);
					assert((size_t)n < sizeof(real_path));
					continue;
				}
			}

			client_submit_response(client,
				GEMINI_STATUS_NOT_FOUND, "Not found", NULL);
			return;
		}

		if (S_ISDIR(st.st_mode)) {
			if (route->autoindex) {
				serve_autoindex(client, real_path);
				return;
			} else {
				strncat(real_path,
					route->index ? route->index : "index.gmi",
					sizeof(real_path) - 1);
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
			ssize_t s = readlink(real_path, temp_path, sizeof(temp_path));
			assert(s != -1);
			strcpy(real_path, temp_path);
		} else if (S_ISREG(st.st_mode)) {
			break;
		} else {
			// Don't serve special files
			client_submit_response(client,
				GEMINI_STATUS_NOT_FOUND, "Not found", NULL);
			return;
		}
	}

	if (route->cgi) {
		serve_cgi(client, real_path,
			(const char *)client_path,
			(const char *)pathinfo);
		return;
	}

	FILE *body = fopen(real_path, "r");
	if (!body) {
		if (errno == ENOENT) {
			client_submit_response(client,
				GEMINI_STATUS_NOT_FOUND, "Not found", NULL);
			return;
		} else {
			client_error(&client->addr, "error opening %s: %s",
					real_path, strerror(errno));
			client_submit_response(client, GEMINI_STATUS_PERMANENT_FAILURE,
				"Internal server error", NULL);
			return;
		}
	}

	const char *meta = mimetype_for_path(real_path);
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
