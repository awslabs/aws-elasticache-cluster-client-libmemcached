//
// Created by Shaul, Bar on 22/03/2022.
//
#if defined(USE_TLS) && USE_TLS
#include <openssl/ssl.h>

#pragma once

struct memc_SSL_CTX {
    /* Associated OpenSSL SSL_CTX as created by memcached_create_ssl_context() */
    SSL_CTX *ctx;

    /* Requested SNI, or NULL */
    char *server_name;
};

/* A wrapper for the openssl's SSL object. */
typedef struct memcached_SSL {
    /* OpenSSL SSL object. */
    SSL *ssl;

    /* Store the default IO functions to switch back to in case TLS is disabled */
    void *default_io_funcs;
} memcached_SSL;

/**
 * SSL context configurations
 */
typedef struct memcached_ssl_context_config {
    char *cert_file;                /* Cert file name */
    char *key_file;                 /* Private key filename for cert_file */
    char *key_file_pass;            /* Optional password for key_file */
    char *ca_cert_file;
    char *ca_cert_dir;
    char *protocols;
    char *ciphers;
    char *ciphersuites;
    int prefer_server_ciphers;
    int session_caching;
    int session_cache_size;
    int session_cache_timeout;
    bool skip_cert_verify;
} memcached_ssl_context_config;
#endif //USE_TLS
