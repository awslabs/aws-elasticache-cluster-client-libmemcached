//
// Created by Shaul, Bar on 17/03/2022.
//

#ifndef AWS_ELASTICACHE_CLUSTER_CLIENT_LIBMEMCACHED_TLS_H
#define AWS_ELASTICACHE_CLUSTER_CLIENT_LIBMEMCACHED_TLS_H

#if defined(USE_TLS) && USE_TLS

#include "common.h"

/**
 * Helper function to initialize the OpenSSL library.
 *
 * OpenSSL requires one-time initialization before it can be used. Callers should
 * call this function only once, and only if OpenSSL is not directly initialized
 * elsewhere.
 */
int memcached_init_OpenSSL(void);

/* The SSL connection context is attached to TLS connections as a privdata. */
typedef struct memcached_ssl {
    /**
     * OpenSSL SSL object.
     */
    SSL *ssl;

    /**
     * SSL_write() requires to be called again with the same arguments it was
     * previously called with in the event of an SSL_read/SSL_write situation
     */
    size_t last_len;

    /** Whether the SSL layer requires read (possibly before a write) */
    int want_read;

    /**
     * Whether a write was requested prior to a read. If set, the write()
     * should resume whenever a read takes place, if possible
     */
    int pending_write;
} memcached_ssl;

/* Forward declaration */
context_funcs context_ssl_funcs;

typedef enum {
    MEMCACHED_SSL_CTX_NONE = 0,                     /* No Error */
    MEMCACHED_SSL_CTX_CREATE_FAILED,                /* Failed to create OpenSSL SSL_CTX */
    MEMCACHED_SSL_CTX_CERT_KEY_REQUIRED,            /* Client cert and key must both be specified or skipped */
    MEMCACHED_SSL_CTX_CA_CERT_LOAD_FAILED,          /* Failed to load CA Certificate or CA Path */
    MEMCACHED_SSL_CTX_CLIENT_CERT_LOAD_FAILED,      /* Failed to load client certificate */
    MEMCACHED_SSL_CTX_PRIVATE_KEY_LOAD_FAILED       /* Failed to load private key */
} memc_ssl_context_error;

/**
 * Return the error message corresponding with the specified error code.
 */
const char *memcached_ssl_context_get_error(memc_ssl_context_error error);

/**
 * Helper function to initialize an OpenSSL context that can be used
 * to initiate SSL connections.
 *
 * cacert_filename is an optional name of a CA certificate/bundle file to load
 * and use for validation.
 *
 * capath is an optional directory path where trusted CA certificate files are
 * stored in an OpenSSL-compatible structure.
 *
 * cert_filename and private_key_filename are optional names of a client side
 * certificate and private key files to use for authentication. They need to
 * be both specified or omitted.
 *
 * If error is non-null, it will be populated in case the context creation fails
 * (returning a NULL).
 */

SSL_CTX *memcached_create_ssl_context(const char *cacert_filename, const char *capath,
        const char *cert_filename, const char *private_key_filename, memc_ssl_context_error *error);

/**
 * Free a memcached_ssl_st object.
 */
static void memcached_ssl_free(void *privctx);

/**
 * Initiate SSL on an existing SSL_CTX.
 * SSL context (SSL_CTX) can be created using the memcached_create_ssl_context() function.
 */

int memc_initiate_ssl_with_context(memcached_instance_st *server, SSL_CTX *ssl_ctx);

#endif //USE_TLS
#endif //AWS_ELASTICACHE_CLUSTER_CLIENT_LIBMEMCACHED_TLS_H
