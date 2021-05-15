#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "config.h"
#include "log.h"
#include "tls.h"
#include "util.h"

static int
always_true_callback(X509_STORE_CTX *ctx, void *arg)
{
	(void)(ctx);
	(void)(arg);
	return 1;
}

static int
tls_host_gencert(struct gmnisrv_tls *tlsconf, struct gmnisrv_host *host,
	const char *crtpath, const char *keypath)
{
	server_log("generating certificate for %s", host->hostname);

	EVP_PKEY *pkey = EVP_PKEY_new();
	assert(pkey);

	EC_KEY* ec_key = EC_KEY_new_by_curve_name(NID_secp384r1);
	assert(ec_key);
	int r = EC_KEY_generate_key(ec_key);
	assert(r == 1);

	EVP_PKEY_assign_EC_KEY(pkey, ec_key);

	X509 * x509 = X509_new();
	assert(x509);

	X509_set_version(x509, 2);
	ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
	X509_gmtime_adj(X509_get_notBefore(x509), 0);
	X509_gmtime_adj(X509_get_notAfter(x509), INT32_MAX); // 68 years
	X509_set_pubkey(x509, pkey);

	char *organization = "gmnisrv";
	if (tlsconf->organization != NULL) {
		organization = tlsconf->organization;
	}
	X509_NAME *name = X509_get_subject_name(x509);
	X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
		(unsigned char *)organization, -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
		(unsigned char *)host->hostname, -1, -1, 0);
	X509_set_issuer_name(x509, name);

	X509V3_CTX ctx;
	X509V3_set_ctx_nodb(&ctx);
	X509V3_set_ctx(&ctx, NULL, x509, NULL, NULL, 0);
	char alt_name[512];
	r = snprintf(alt_name, sizeof(alt_name), "DNS:%s", host->hostname);
	assert(r >= 0 && (size_t)r < sizeof(alt_name));
	X509_EXTENSION* ext = X509V3_EXT_conf_nid(NULL, &ctx,
		NID_subject_alt_name, alt_name);
	assert(ext);
	X509_add_ext(x509, ext, -1);
	X509_EXTENSION_free(ext);

	r = X509_sign(x509, pkey, EVP_sha256());
	assert(r);

	int pfd = open(keypath, O_CREAT | O_WRONLY, 0600);
	if (pfd < 0) {
		server_error("opening private key for writing failed: %s",
			strerror(errno));
		return 1;
	}

	FILE *pf = fdopen(pfd, "w");
	assert(pf);

	r = PEM_write_PrivateKey(pf, pkey, NULL, NULL, 0, NULL, NULL);
	fclose(pf);
	if (r != 1) {
		server_error("writing private key failed");
		return 1;
	}

	FILE *xf = fopen(crtpath, "w");
	if (!xf) {
		server_error("opening certificate for writing failed: %s",
			strerror(errno));
		return 1;
	}
	r = PEM_write_X509(xf, x509);
	fclose(xf);
	if (r != 1) {
		server_error("writing private key failed");
		return 1;
	}

	host->x509 = x509;
	host->pkey = pkey;
	return 0;
}

static int
tls_host_init(struct gmnisrv_tls *tlsconf, struct gmnisrv_host *host)
{
	char crtpath[PATH_MAX + 1];
	char keypath[PATH_MAX + 1];
	snprintf(crtpath, sizeof(crtpath),
		"%s/%s.crt", tlsconf->store, host->hostname);
	snprintf(keypath, sizeof(keypath),
		"%s/%s.key", tlsconf->store, host->hostname);
	mkdirs(tlsconf->store, 0755);

	FILE *xf = fopen(crtpath, "r");
	if (!xf && errno != ENOENT) {
		server_error("error opening %s for reading: %s",
			crtpath, strerror(errno));
		return 1;
	} else if (!xf) {
		goto generate;
	}
	FILE *kf = fopen(keypath, "r");
	if (!kf && errno != ENOENT) {
		server_error("error opening %s for reading: %s",
			keypath, strerror(errno));
		fclose(xf);
		return 1;
	} else if (!kf) {
		fclose(xf);
		goto generate;
	}

	X509 *x509 = PEM_read_X509(xf, NULL, NULL, NULL);
	fclose(xf);
	if (!x509) {
		server_error("error loading certificate from %s", crtpath);
		fclose(kf);
		return 1;
	}

	EVP_PKEY *pkey = PEM_read_PrivateKey(kf, NULL, NULL, NULL);
	fclose(kf);
	if (!pkey) {
		server_error("error loading private key from %s", keypath);
		return 1;
	}

	int day, sec;
	const ASN1_TIME *notAfter = X509_get0_notAfter(x509);
	int r = ASN1_TIME_diff(&day, &sec, NULL, notAfter);
	assert(r == 1);
	if (day < 0 || sec < 0) {
		server_log("%s certificate is expired", host->hostname);
		goto generate;
	}

	host->x509 = x509;
	host->pkey = pkey;
	server_log("loaded certificate for %s", host->hostname);
	return 0;

generate:
	return tls_host_gencert(tlsconf, host, crtpath, keypath);
}

int
tls_init(struct gmnisrv_config *conf)
{
	SSL_load_error_strings();
	ERR_load_crypto_strings();

	conf->tls.ssl_ctx = SSL_CTX_new(TLS_server_method());
	assert(conf->tls.ssl_ctx);

	int r = SSL_CTX_set_min_proto_version(conf->tls.ssl_ctx, TLS1_2_VERSION);
	assert(r == 1);

	r = SSL_CTX_set_cipher_list(conf->tls.ssl_ctx,
		"ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
		"ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
		"ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
		"DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:"
		"TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:"
		"TLS_CHACHA20_POLY1305_SHA256");
	assert(r == 1);

	SSL_CTX_set_tlsext_servername_callback(conf->tls.ssl_ctx, NULL);
	SSL_CTX_set_verify(conf->tls.ssl_ctx, SSL_VERIFY_PEER, NULL);
	// use always_true_callback to ignore errors such as self-signed error
	SSL_CTX_set_cert_verify_callback(conf->tls.ssl_ctx, always_true_callback, NULL);

	// TLS re-negotiation is a fucking STUPID idea
	// I'm gating this behind an #ifdef based on an optimistic assumption
	// that someday it will be removed from OpenSSL entirely because of how
	// fucking stupid this fucking godawful idea is
#ifdef SSL_OP_NO_RENEGOTIATION
	SSL_CTX_set_options(conf->tls.ssl_ctx, SSL_OP_NO_RENEGOTIATION);
#endif

	for (struct gmnisrv_host *host = conf->hosts; host; host = host->next) {
		r = tls_host_init(&conf->tls, host);
		if (r != 0) {
			return r;
		}
	}

	return 0;
}

void
tls_finish(struct gmnisrv_config *conf)
{
	SSL_CTX_free(conf->tls.ssl_ctx);
	for (struct gmnisrv_host *host = conf->hosts; host; host = host->next) {
		X509_free(host->x509);
		EVP_PKEY_free(host->pkey);
	}
}

SSL *
tls_get_ssl(struct gmnisrv_config *conf)
{
	return SSL_new(conf->tls.ssl_ctx);
}

void
tls_set_host(SSL *ssl, struct gmnisrv_host *host)
{
	SSL_use_certificate(ssl, host->x509);
	SSL_use_PrivateKey(ssl, host->pkey);
}
