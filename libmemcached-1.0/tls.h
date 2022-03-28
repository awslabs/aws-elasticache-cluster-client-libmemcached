//
// Created by Shaul, Bar on 22/03/2022.
//

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <libmemcached-1.0/visibility.h>
#include <libmemcached-1.0/struct/tls.h>
#include <libmemcached-1.0/types.h>

#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/opensslv.h>

#include <libmemcached-1.0/types.h>
#include <libmemcached-1.0/types/return.h>

/**
 * To create a Memcached client instance with TLS follow the following steps:
    #include <libmemcached/memcached.h>
    memcached_server_st *servers = NULL;
    memcached_st *memc;
    memcached_return rc;
    memc_ssl_context_error error;
    memcached_ssl_context_config *config;
    memc = memcached_create(NULL);

    // Set SSL configurations
    config->cert_file = "/path/to/cert";
    config->key_file = "/path/to/key";

    memc_SSL_CTX *ssl_ctx = memcached_create_ssl_context(memc, config , &error);
    if (ssl_ctx == NULL) {
        fprintf(stderr,memcached_ssl_context_get_error(error));
    }

    servers= memcached_server_list_append(servers, "localhost", 6379, &rc);
    memcached_server_push(memc, servers);

    rc = memcached_set_ssl_context(memc, ssl_ctx);
    if (rc != MEMCACHED_SUCCESS) {
        fprintf(stderr, memcached_strerror(NULL, rc));
    }
 */


/**
 * Helper function to initialize the OpenSSL library.
 *
 * OpenSSL requires one-time initialization before it can be used. Callers should
 * call this function only once, and only if OpenSSL is not directly initialized
 * elsewhere.
 */
LIBMEMCACHED_API
int memcached_init_OpenSSL(void);

/**
 * Return the error message corresponding with the specified error code.
 */
LIBMEMCACHED_API
const char *memcached_ssl_context_get_error(memc_ssl_context_error error);




LIBMEMCACHED_API
void memc_free_SSL_ctx(memc_SSL_CTX *ssl_ctx);


/**
 * Create a memc_SSL_CTX with a base SSL_CTX (OpenSSL context) using the SSL configuration provided.
 *
 * If ptr is non-null, the calloc function configured in the memcached instance will be used to allocate memory.
 * Otherwise, std::calloc will be used.
 *
 * If error is non-null, it will be populated in case the context creation fails
 * (returning a NULL).
 *
 * This function DOESN'T set the SSL context to the passed memcached instance. To do so, call the
 * memcached_set_ssl_context() function.
 * */

LIBMEMCACHED_API
memc_SSL_CTX *memcached_create_ssl_context(const memcached_st *ptr, memcached_ssl_context_config *ctx_config, memc_ssl_context_error *error);

/**
 * Free a memcached_ssl_st object.
 */
LIBMEMCACHED_API
void memcached_ssl_free(void *privctx);

memcached_return_t memc_initiate_ssl(memcached_instance_st *server);

memcached_return_t memcached_ssl_connect(memcached_instance_st *server, SSL *ssl);

/**
 * Set the SSL context to the passed Memcached instance.
 * This function also sets MEMCACHED_BEHAVIOR_USE_TLS to true.
 */
LIBMEMCACHED_API
memcached_return_t memcached_set_ssl_context(memcached_st *ptr, memc_SSL_CTX *ssl_ctx);

LIBMEMCACHED_API
ssize_t memcached_ssl_write(memcached_instance_st* instance,
             char* local_write_ptr,
             size_t write_length,
             int flags);

LIBMEMCACHED_API
ssize_t memcached_ssl_read(memcached_instance_st* instance,
             char* input_buf,
             size_t buffer_length,
             int flags);

SSL_CTX* init_ctx(void);

LIBMEMCACHED_API
memcached_return_t memcached_ssl_get_server_certs(memcached_instance_st * instance, char * output);

#ifdef __cplusplus
} // extern "C"
#endif

