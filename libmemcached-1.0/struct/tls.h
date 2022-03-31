//
// Created by Shaul, Bar on 22/03/2022.
//

#ifndef AWS_ELASTICACHE_CLUSTER_CLIENT_LIBMEMCACHED_TLS_H
#define AWS_ELASTICACHE_CLUSTER_CLIENT_LIBMEMCACHED_TLS_H

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
    /**
     * OpenSSL SSL object.
     */
    SSL *ssl;

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

#endif //AWS_ELASTICACHE_CLUSTER_CLIENT_LIBMEMCACHED_TLS_H