#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "config.h"
#include "log.h"
#include "tls.h"
#include "util.h"

static int
tls_host_gencert(struct gmnisrv_tls *tlsconf, struct gmnisrv_host *host,
	const char *crtpath, const char *keypath)
{
	server_log("generating certificate for %s", host->hostname);

	EVP_PKEY *pkey = EVP_PKEY_new();
	assert(pkey);

	BIGNUM *bn = BN_new();
	assert(bn);
	BN_set_word(bn, RSA_F4);

	RSA* rsa = RSA_new();
	assert(rsa);
	int r = RSA_generate_key_ex(rsa, 4096, bn, NULL);
	assert(r == 1);
	BN_free(bn);

	EVP_PKEY_assign_RSA(pkey, rsa);

	X509 * x509 = X509_new();
	assert(x509);

	ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
	X509_gmtime_adj(X509_get_notBefore(x509), 0);
	X509_gmtime_adj(X509_get_notAfter(x509), 31536000L); // 1 year
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

	r = X509_sign(x509, pkey, EVP_sha256());
	assert(r);

	int pfd = open(keypath, O_CREAT | O_WRONLY, 0600);
	if (!pfd) {
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
gmnisrv_tls_init(struct gmnisrv_config *conf)
{
	SSL_load_error_strings();
	ERR_load_crypto_strings();

	conf->tls.ssl_ctx = SSL_CTX_new(TLS_method());
	assert(conf->tls.ssl_ctx);

	SSL_CTX_set_tlsext_servername_callback(conf->tls.ssl_ctx, NULL);

	int r;
	for (struct gmnisrv_host *host = conf->hosts; host; host = host->next) {
		r = tls_host_init(&conf->tls, host);
		if (r != 0) {
			return r;
		}
	}

	return 0;
}

SSL *
gmnisrv_tls_get_ssl(struct gmnisrv_config *conf, int fd)
{
	SSL *ssl = SSL_new(conf->tls.ssl_ctx);
	if (!ssl) {
		return NULL;
	}
	int r = SSL_set_fd(ssl, fd);
	assert(r == 1);
	return ssl;
}

void
gmnisrv_tls_set_host(SSL *ssl, struct gmnisrv_host *host)
{
	SSL_use_certificate(ssl, host->x509);
	SSL_use_PrivateKey(ssl, host->pkey);
}
