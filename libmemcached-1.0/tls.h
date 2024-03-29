/**
 * Copyright (C) 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#if defined(USE_TLS) && USE_TLS

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <libmemcached-1.0/visibility.h>
#include <libmemcached-1.0/struct/tls.h>
#include <libmemcached-1.0/types.h>
#include <libmemcached-1.0/types/return.h>
/**
 * See example/tls_client.cc for usage example
 */


/**
 * Helper function to initialize the OpenSSL library.
 *
 * OpenSSL requires one-time initialization before it can be used. Callers should
 * call this function only once, and only if OpenSSL is not directly initialized
 * elsewhere.
 */
LIBMEMCACHED_API
int memcached_init_openssl(void);

/**
 * Return the error message corresponding with the specified error code.
 */
LIBMEMCACHED_API
const char *memcached_ssl_context_get_error(memc_ssl_context_error error);

/**
 * Free the memory of the passed ssl_ctx.
 * ptr (memcached_st) is used to determined the memory destructors.
 * ptr can be set to NULL to use the default destructors.
 */
LIBMEMCACHED_API
void _memcached_free_ssl_ctx(const memcached_st *ptr, memcached_SSL_CTX *ssl_ctx);

/**
 * Free the ssl_ctx memory of the passed memcached object.
 */
void memcached_free_ssl_ctx(memcached_st* memc);

/**
 * Create a memcached_SSL_CTX with a base SSL_CTX (OpenSSL context) using the SSL configuration provided.
 * Sets the created memcached_SSL_CTX to the memcached instance.
 *
 * The calloc function configured in the memcached instance will be used to allocate memory.
 *
 * Returns a memc_ssl_context_error. If SSL_CTX set and creation was successful, MEMCACHED_SSL_CTX_SUCCESS will be returned.
 *
 * */
LIBMEMCACHED_API
memc_ssl_context_error memcached_create_and_set_ssl_context(memcached_st *ptr, memcached_ssl_context_config *config);

/**
 * Gets a copy of the memcached SSL context (memcached_SSL_CTX) of the memcached instance.
 * SSL_CTX reference count is increased by this function.
 * NULL is returned if memcached_SSL_CTX isn't set.
 */
LIBMEMCACHED_API
        memcached_SSL_CTX *memcached_get_ssl_context_copy(const memcached_st *ptr);

/**
 * Get the server's SSL certificates.
 * The function allocates memory Using memcached_st's malloc function and "output" should be freed by the user.
 */
LIBMEMCACHED_API
memcached_return_t memcached_ssl_get_server_certs(memcached_instance_st * instance, char * output);

/**
 * Initialize SSL connection
 */
memcached_return_t memcached_ssl_connect(memcached_instance_st *server);

/**
 * Set the SSL context to the passed Memcached instance.
 * This function also sets MEMCACHED_BEHAVIOR_USE_TLS to true.
 */
LIBMEMCACHED_API
memcached_return_t memcached_set_ssl_context(memcached_st *ptr, memcached_SSL_CTX *ssl_ctx);


/**
 * SSL read function to be used with context_funcs.write
 */
ssize_t memcached_ssl_write(memcached_instance_st* instance,
             char* local_write_ptr,
             size_t write_length,
             int flags);

/**
 * SSL read function to be used with context_funcs.read
 */
ssize_t memcached_ssl_read(memcached_instance_st* instance,
             char* input_buf,
             size_t buffer_length,
             int flags);

/**
 * Free a memcached_ssl_st object.
 */
void memcached_free_ssl(memcached_instance_st *instance);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // USE_TLS
