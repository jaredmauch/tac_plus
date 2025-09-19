/*
 * $Id: tls_support.c,v 1.1 2024-01-01 00:00:00 tac_plus Exp $
 *
 * Copyright (c) Facebook, Inc. and its affiliates. All Rights Reserved
 * Copyright (c) 1995-1998 by Cisco systems, Inc.
 *
 * Permission to use, copy, modify, and distribute this software for
 * any purpose and without fee is hereby granted, provided that this
 * copyright and permission notice appear on all copies of the
 * software and supporting documentation, the name of Cisco Systems,
 * Inc. not be used in advertising or publicity pertaining to
 * distribution of the program without specific prior permission, and
 * notice be given in supporting documentation that modification,
 * copying and distribution is by permission of Cisco Systems, Inc.
 *
 * Cisco Systems, Inc. makes no representations about the suitability
 * of this software for any purpose.  THIS SOFTWARE IS PROVIDED ``AS
 * IS'' AND WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING,
 * WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
 * FITNESS FOR A PARTICULAR PURPOSE.
 */

/*
 * tls_support.c - TLS transport security support for RFC 8907 compliance
 */

#include "config.h"
#include "tacacs.h"
#include "tac_plus.h"

#ifdef HAVE_TLS

#ifdef HAVE_OPENSSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#endif

#ifdef HAVE_MBEDTLS
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/certs.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/pk.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/* TLS context structure */
struct tls_context {
#ifdef HAVE_OPENSSL
    SSL_CTX *ssl_ctx;
    SSL *ssl;
#endif
#ifdef HAVE_MBEDTLS
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_x509_crt srvcert;
    mbedtls_x509_crt cacert;
    mbedtls_pk_context pkey;
#endif
    int socket_fd;
    int is_server;
    int is_connected;
};

/* Global TLS context */
static struct tls_context *tls_ctx = NULL;

/* Forward declarations */
static int tls_init_openssl(void);
static int tls_init_mbedtls(void);
static int tls_reload_openssl(void);
static int tls_reload_mbedtls(void);
static void tls_cleanup_openssl(void);
static void tls_cleanup_mbedtls(void);

/*
 * Initialize TLS support
 */
int
tls_init(void)
{
    if (tls_ctx != NULL) {
        return 0; /* Already initialized */
    }

    tls_ctx = calloc(1, sizeof(struct tls_context));
    if (tls_ctx == NULL) {
        report(LOG_ERR, "tls_init: Failed to allocate TLS context");
        return -1;
    }

#ifdef HAVE_OPENSSL
    if (tls_init_openssl() != 0) {
        free(tls_ctx);
        tls_ctx = NULL;
        return -1;
    }
#endif

#ifdef HAVE_MBEDTLS
    if (tls_init_mbedtls() != 0) {
        free(tls_ctx);
        tls_ctx = NULL;
        return -1;
    }
#endif

    return 0;
}

/*
 * Reload TLS certificates and configuration
 */
int
tls_reload(void)
{
    if (tls_ctx == NULL) {
        report(LOG_WARNING, "tls_reload: TLS not initialized, initializing now");
        return tls_init();
    }

    report(LOG_INFO, "Reloading TLS certificates and configuration");

#ifdef HAVE_OPENSSL
    if (tls_reload_openssl() != 0) {
        report(LOG_ERR, "tls_reload: Failed to reload OpenSSL configuration");
        return -1;
    }
#endif

#ifdef HAVE_MBEDTLS
    if (tls_reload_mbedtls() != 0) {
        report(LOG_ERR, "tls_reload: Failed to reload mbedTLS configuration");
        return -1;
    }
#endif

    report(LOG_INFO, "TLS certificates and configuration reloaded successfully");
    return 0;
}

/*
 * Cleanup TLS support
 */
void
tls_cleanup(void)
{
    if (tls_ctx == NULL) {
        return;
    }

#ifdef HAVE_OPENSSL
    tls_cleanup_openssl();
#endif

#ifdef HAVE_MBEDTLS
    tls_cleanup_mbedtls();
#endif

    free(tls_ctx);
    tls_ctx = NULL;
}

/*
 * Accept TLS connection (server side)
 */
int
tls_accept(int socket_fd)
{
    if (tls_ctx == NULL) {
        report(LOG_ERR, "tls_accept: TLS not initialized");
        return -1;
    }

    tls_ctx->socket_fd = socket_fd;
    tls_ctx->is_server = 1;

#ifdef HAVE_OPENSSL
    tls_ctx->ssl = SSL_new(tls_ctx->ssl_ctx);
    if (tls_ctx->ssl == NULL) {
        report(LOG_ERR, "tls_accept: Failed to create SSL object");
        return -1;
    }

    if (SSL_set_fd(tls_ctx->ssl, socket_fd) != 1) {
        report(LOG_ERR, "tls_accept: Failed to set SSL file descriptor");
        SSL_free(tls_ctx->ssl);
        tls_ctx->ssl = NULL;
        return -1;
    }

    if (SSL_accept(tls_ctx->ssl) <= 0) {
        report(LOG_ERR, "tls_accept: SSL handshake failed");
        SSL_free(tls_ctx->ssl);
        tls_ctx->ssl = NULL;
        return -1;
    }
#endif

#ifdef HAVE_MBEDTLS
    mbedtls_ssl_set_bio(&tls_ctx->ssl, &socket_fd, mbedtls_net_send, mbedtls_net_recv, NULL);
    
    if (mbedtls_ssl_handshake(&tls_ctx->ssl) != 0) {
        report(LOG_ERR, "tls_accept: mbedTLS handshake failed");
        return -1;
    }
#endif

    tls_ctx->is_connected = 1;
    return 0;
}

/*
 * Connect with TLS (client side)
 */
int
tls_connect(int socket_fd)
{
    if (tls_ctx == NULL) {
        report(LOG_ERR, "tls_connect: TLS not initialized");
        return -1;
    }

    tls_ctx->socket_fd = socket_fd;
    tls_ctx->is_server = 0;

#ifdef HAVE_OPENSSL
    tls_ctx->ssl = SSL_new(tls_ctx->ssl_ctx);
    if (tls_ctx->ssl == NULL) {
        report(LOG_ERR, "tls_connect: Failed to create SSL object");
        return -1;
    }

    if (SSL_set_fd(tls_ctx->ssl, socket_fd) != 1) {
        report(LOG_ERR, "tls_connect: Failed to set SSL file descriptor");
        SSL_free(tls_ctx->ssl);
        tls_ctx->ssl = NULL;
        return -1;
    }

    if (SSL_connect(tls_ctx->ssl) <= 0) {
        report(LOG_ERR, "tls_connect: SSL handshake failed");
        SSL_free(tls_ctx->ssl);
        tls_ctx->ssl = NULL;
        return -1;
    }
#endif

#ifdef HAVE_MBEDTLS
    mbedtls_ssl_set_bio(&tls_ctx->ssl, &socket_fd, mbedtls_net_send, mbedtls_net_recv, NULL);
    
    if (mbedtls_ssl_handshake(&tls_ctx->ssl) != 0) {
        report(LOG_ERR, "tls_connect: mbedTLS handshake failed");
        return -1;
    }
#endif

    tls_ctx->is_connected = 1;
    return 0;
}

/*
 * Read data over TLS
 */
int
tls_read(void *buf, int len)
{
    if (tls_ctx == NULL || !tls_ctx->is_connected) {
        return -1;
    }

#ifdef HAVE_OPENSSL
    return SSL_read(tls_ctx->ssl, buf, len);
#endif

#ifdef HAVE_MBEDTLS
    return mbedtls_ssl_read(&tls_ctx->ssl, (unsigned char *)buf, len);
#endif

    return -1;
}

/*
 * Write data over TLS
 */
int
tls_write(const void *buf, int len)
{
    if (tls_ctx == NULL || !tls_ctx->is_connected) {
        return -1;
    }

#ifdef HAVE_OPENSSL
    return SSL_write(tls_ctx->ssl, buf, len);
#endif

#ifdef HAVE_MBEDTLS
    return mbedtls_ssl_write(&tls_ctx->ssl, (const unsigned char *)buf, len);
#endif

    return -1;
}

/*
 * Close TLS connection
 */
void
tls_close(void)
{
    if (tls_ctx == NULL || !tls_ctx->is_connected) {
        return;
    }

#ifdef HAVE_OPENSSL
    if (tls_ctx->ssl) {
        SSL_shutdown(tls_ctx->ssl);
        SSL_free(tls_ctx->ssl);
        tls_ctx->ssl = NULL;
    }
#endif

#ifdef HAVE_MBEDTLS
    mbedtls_ssl_close_notify(&tls_ctx->ssl);
#endif

    tls_ctx->is_connected = 0;
}

/*
 * Check if TLS is connected
 */
int
tls_is_connected(void)
{
    return (tls_ctx != NULL && tls_ctx->is_connected) ? 1 : 0;
}

#ifdef HAVE_OPENSSL
/*
 * Initialize OpenSSL TLS support
 */
static int
tls_init_openssl(void)
{
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    tls_ctx->ssl_ctx = SSL_CTX_new(TLS_server_method());
    if (tls_ctx->ssl_ctx == NULL) {
        report(LOG_ERR, "tls_init_openssl: Failed to create SSL context");
        return -1;
    }

    /* Load server certificate */
    if (SSL_CTX_use_certificate_file(tls_ctx->ssl_ctx, TLS_CERT_PATH, SSL_FILETYPE_PEM) != 1) {
        report(LOG_ERR, "tls_init_openssl: Failed to load server certificate from %s", TLS_CERT_PATH);
        return -1;
    }

    /* Load server private key */
    if (SSL_CTX_use_PrivateKey_file(tls_ctx->ssl_ctx, TLS_KEY_PATH, SSL_FILETYPE_PEM) != 1) {
        report(LOG_ERR, "tls_init_openssl: Failed to load server private key from %s", TLS_KEY_PATH);
        return -1;
    }

    /* Verify private key matches certificate */
    if (SSL_CTX_check_private_key(tls_ctx->ssl_ctx) != 1) {
        report(LOG_ERR, "tls_init_openssl: Private key does not match certificate");
        return -1;
    }

    /* Load CA certificate for client verification */
    if (SSL_CTX_load_verify_locations(tls_ctx->ssl_ctx, TLS_CA_PATH, NULL) != 1) {
        report(LOG_WARNING, "tls_init_openssl: Failed to load CA certificate from %s", TLS_CA_PATH);
    }

    /* Require client certificate verification */
    SSL_CTX_set_verify(tls_ctx->ssl_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

    /* Set minimum TLS version to 1.3 (RFC 8907 compliance) */
    SSL_CTX_set_min_proto_version(tls_ctx->ssl_ctx, TLS1_3_VERSION);

    /* Disable compression to prevent CRIME attacks */
    SSL_CTX_set_options(tls_ctx->ssl_ctx, SSL_OP_NO_COMPRESSION);

    /* Disable session tickets for better security */
    SSL_CTX_set_options(tls_ctx->ssl_ctx, SSL_OP_NO_TICKET);

    /* Set secure cipher list (TLS 1.3 only) */
    if (SSL_CTX_set_ciphersuites(tls_ctx->ssl_ctx, "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256") != 1) {
        report(LOG_WARNING, "tls_init_openssl: Failed to set cipher suites, using defaults");
    }

    return 0;
}

/*
 * Cleanup OpenSSL TLS support
 */
static void
tls_cleanup_openssl(void)
{
    if (tls_ctx->ssl_ctx) {
        SSL_CTX_free(tls_ctx->ssl_ctx);
        tls_ctx->ssl_ctx = NULL;
    }
    
    EVP_cleanup();
    ERR_free_strings();
}

/*
 * Reload OpenSSL TLS configuration
 */
static int
tls_reload_openssl(void)
{
    if (tls_ctx == NULL || tls_ctx->ssl_ctx == NULL) {
        report(LOG_ERR, "tls_reload_openssl: TLS context not initialized");
        return -1;
    }

    /* Get certificate paths from configuration or use defaults */
    const char *cert_path = tls_cert_path ? tls_cert_path : TLS_CERT_PATH;
    const char *key_path = tls_key_path ? tls_key_path : TLS_KEY_PATH;
    const char *ca_path = tls_ca_path ? tls_ca_path : TLS_CA_PATH;

    /* Validate certificate files exist and are readable */
    if (access(cert_path, R_OK) != 0) {
        report(LOG_ERR, "tls_reload_openssl: Server certificate file not readable: %s", cert_path);
        return -1;
    }
    if (access(key_path, R_OK) != 0) {
        report(LOG_ERR, "tls_reload_openssl: Server private key file not readable: %s", key_path);
        return -1;
    }
    if (access(ca_path, R_OK) != 0) {
        report(LOG_WARNING, "tls_reload_openssl: CA certificate file not readable: %s", ca_path);
    }

    /* Create new SSL context */
    SSL_CTX *new_ctx = SSL_CTX_new(TLS_server_method());
    if (new_ctx == NULL) {
        report(LOG_ERR, "tls_reload_openssl: Failed to create new SSL context");
        return -1;
    }

    /* Load server certificate */
    if (SSL_CTX_use_certificate_file(new_ctx, cert_path, SSL_FILETYPE_PEM) != 1) {
        report(LOG_ERR, "tls_reload_openssl: Failed to load server certificate from %s", cert_path);
        SSL_CTX_free(new_ctx);
        return -1;
    }

    /* Load server private key */
    if (SSL_CTX_use_PrivateKey_file(new_ctx, key_path, SSL_FILETYPE_PEM) != 1) {
        report(LOG_ERR, "tls_reload_openssl: Failed to load server private key from %s", key_path);
        SSL_CTX_free(new_ctx);
        return -1;
    }

    /* Verify private key matches certificate */
    if (SSL_CTX_check_private_key(new_ctx) != 1) {
        report(LOG_ERR, "tls_reload_openssl: Private key does not match certificate");
        SSL_CTX_free(new_ctx);
        return -1;
    }

    /* Load CA certificate for client verification */
    if (SSL_CTX_load_verify_locations(new_ctx, ca_path, NULL) != 1) {
        report(LOG_WARNING, "tls_reload_openssl: Failed to load CA certificate from %s", ca_path);
    }

    /* Apply same security settings as initialization */
    SSL_CTX_set_verify(new_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    SSL_CTX_set_min_proto_version(new_ctx, TLS1_3_VERSION);
    SSL_CTX_set_options(new_ctx, SSL_OP_NO_COMPRESSION | SSL_OP_NO_TICKET);
    
    if (SSL_CTX_set_ciphersuites(new_ctx, "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256") != 1) {
        report(LOG_WARNING, "tls_reload_openssl: Failed to set cipher suites, using defaults");
    }

    /* Replace old context with new one */
    SSL_CTX_free(tls_ctx->ssl_ctx);
    tls_ctx->ssl_ctx = new_ctx;

    report(LOG_INFO, "OpenSSL TLS configuration reloaded successfully");
    return 0;
}
#endif

#ifdef HAVE_MBEDTLS
/*
 * Initialize mbedTLS support
 */
static int
tls_init_mbedtls(void)
{
    int ret;

    mbedtls_ssl_init(&tls_ctx->ssl);
    mbedtls_ssl_config_init(&tls_ctx->conf);
    mbedtls_entropy_init(&tls_ctx->entropy);
    mbedtls_ctr_drbg_init(&tls_ctx->ctr_drbg);
    mbedtls_x509_crt_init(&tls_ctx->srvcert);
    mbedtls_x509_crt_init(&tls_ctx->cacert);
    mbedtls_pk_init(&tls_ctx->pkey);

    /* Seed random number generator */
    if ((ret = mbedtls_ctr_drbg_seed(&tls_ctx->ctr_drbg, mbedtls_entropy_func, &tls_ctx->entropy,
                                     (const unsigned char *) "tac_plus", 8)) != 0) {
        report(LOG_ERR, "tls_init_mbedtls: mbedtls_ctr_drbg_seed failed: %d", ret);
        return -1;
    }

    /* Load server certificate */
    if ((ret = mbedtls_x509_crt_parse_file(&tls_ctx->srvcert, TLS_CERT_PATH)) != 0) {
        report(LOG_ERR, "tls_init_mbedtls: Failed to load server certificate from %s: %d", TLS_CERT_PATH, ret);
        return -1;
    }

    /* Load server private key */
    if ((ret = mbedtls_pk_parse_keyfile(&tls_ctx->pkey, TLS_KEY_PATH, NULL)) != 0) {
        report(LOG_ERR, "tls_init_mbedtls: Failed to load server private key from %s: %d", TLS_KEY_PATH, ret);
        return -1;
    }

    /* Load CA certificate for client verification */
    if ((ret = mbedtls_x509_crt_parse_file(&tls_ctx->cacert, TLS_CA_PATH)) != 0) {
        report(LOG_WARNING, "tls_init_mbedtls: Failed to load CA certificate from %s: %d", TLS_CA_PATH, ret);
    }

    /* Configure SSL */
    if ((ret = mbedtls_ssl_config_defaults(&tls_ctx->conf, MBEDTLS_SSL_IS_SERVER,
                                          MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        report(LOG_ERR, "tls_init_mbedtls: mbedtls_ssl_config_defaults failed: %d", ret);
        return -1;
    }

    /* Set minimum TLS version to 1.3 (RFC 8907 compliance) */
    mbedtls_ssl_conf_min_version(&tls_ctx->conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_4);

    /* Set maximum TLS version to 1.3 (no older versions) */
    mbedtls_ssl_conf_max_version(&tls_ctx->conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_4);

    /* Disable compression to prevent CRIME attacks */
    mbedtls_ssl_conf_compression(&tls_ctx->conf, MBEDTLS_SSL_COMPRESS_NONE);

    /* Set RNG */
    mbedtls_ssl_conf_rng(&tls_ctx->conf, mbedtls_ctr_drbg_random, &tls_ctx->ctr_drbg);

    /* Set certificates */
    mbedtls_ssl_conf_ca_chain(&tls_ctx->conf, &tls_ctx->cacert, NULL);
    if ((ret = mbedtls_ssl_conf_own_cert(&tls_ctx->conf, &tls_ctx->srvcert, &tls_ctx->pkey)) != 0) {
        report(LOG_ERR, "tls_init_mbedtls: mbedtls_ssl_conf_own_cert failed: %d", ret);
        return -1;
    }

    /* Require client certificate verification */
    mbedtls_ssl_conf_authmode(&tls_ctx->conf, MBEDTLS_SSL_VERIFY_REQUIRED);

    /* Set up SSL context */
    if ((ret = mbedtls_ssl_setup(&tls_ctx->ssl, &tls_ctx->conf)) != 0) {
        report(LOG_ERR, "tls_init_mbedtls: mbedtls_ssl_setup failed: %d", ret);
        return -1;
    }

    return 0;
}

/*
 * Reload mbedTLS TLS configuration
 */
static int
tls_reload_mbedtls(void)
{
    if (tls_ctx == NULL) {
        report(LOG_ERR, "tls_reload_mbedtls: TLS context not initialized");
        return -1;
    }

    /* Get certificate paths from configuration or use defaults */
    const char *cert_path = tls_cert_path ? tls_cert_path : TLS_CERT_PATH;
    const char *key_path = tls_key_path ? tls_key_path : TLS_KEY_PATH;
    const char *ca_path = tls_ca_path ? tls_ca_path : TLS_CA_PATH;

    /* Validate certificate files exist and are readable */
    if (access(cert_path, R_OK) != 0) {
        report(LOG_ERR, "tls_reload_mbedtls: Server certificate file not readable: %s", cert_path);
        return -1;
    }
    if (access(key_path, R_OK) != 0) {
        report(LOG_ERR, "tls_reload_mbedtls: Server private key file not readable: %s", key_path);
        return -1;
    }
    if (access(ca_path, R_OK) != 0) {
        report(LOG_WARNING, "tls_reload_mbedtls: CA certificate file not readable: %s", ca_path);
    }

    int ret;

    /* Clean up old certificates */
    mbedtls_x509_crt_free(&tls_ctx->srvcert);
    mbedtls_x509_crt_free(&tls_ctx->cacert);
    mbedtls_pk_free(&tls_ctx->pkey);

    /* Reinitialize certificate structures */
    mbedtls_x509_crt_init(&tls_ctx->srvcert);
    mbedtls_x509_crt_init(&tls_ctx->cacert);
    mbedtls_pk_init(&tls_ctx->pkey);

    /* Load server certificate */
    if ((ret = mbedtls_x509_crt_parse_file(&tls_ctx->srvcert, cert_path)) != 0) {
        report(LOG_ERR, "tls_reload_mbedtls: Failed to load server certificate from %s: %d", cert_path, ret);
        return -1;
    }

    /* Load server private key */
    if ((ret = mbedtls_pk_parse_keyfile(&tls_ctx->pkey, key_path, NULL)) != 0) {
        report(LOG_ERR, "tls_reload_mbedtls: Failed to load server private key from %s: %d", key_path, ret);
        return -1;
    }

    /* Load CA certificate for client verification */
    if ((ret = mbedtls_x509_crt_parse_file(&tls_ctx->cacert, ca_path)) != 0) {
        report(LOG_WARNING, "tls_reload_mbedtls: Failed to load CA certificate from %s: %d", ca_path, ret);
    }

    /* Update SSL configuration with new certificates */
    mbedtls_ssl_conf_ca_chain(&tls_ctx->conf, &tls_ctx->cacert, NULL);
    if ((ret = mbedtls_ssl_conf_own_cert(&tls_ctx->conf, &tls_ctx->srvcert, &tls_ctx->pkey)) != 0) {
        report(LOG_ERR, "tls_reload_mbedtls: mbedtls_ssl_conf_own_cert failed: %d", ret);
        return -1;
    }

    report(LOG_INFO, "mbedTLS TLS configuration reloaded successfully");
    return 0;
}

/*
 * Cleanup mbedTLS support
 */
static void
tls_cleanup_mbedtls(void)
{
    mbedtls_ssl_free(&tls_ctx->ssl);
    mbedtls_ssl_config_free(&tls_ctx->conf);
    mbedtls_entropy_free(&tls_ctx->entropy);
    mbedtls_ctr_drbg_free(&tls_ctx->ctr_drbg);
    mbedtls_x509_crt_free(&tls_ctx->srvcert);
    mbedtls_x509_crt_free(&tls_ctx->cacert);
    mbedtls_pk_free(&tls_ctx->pkey);
}
#endif

#else /* !HAVE_TLS */

/*
 * Stub functions when TLS is not available
 */
int tls_init(void) { return -1; }
int tls_reload(void) { return -1; }
void tls_cleanup(void) { }
int tls_accept(int socket_fd) { return -1; }
int tls_connect(int socket_fd) { return -1; }
int tls_read(void *buf, int len) { return -1; }
int tls_write(const void *buf, int len) { return -1; }
void tls_close(void) { }
int tls_is_connected(void) { return 0; }

#endif /* HAVE_TLS */
