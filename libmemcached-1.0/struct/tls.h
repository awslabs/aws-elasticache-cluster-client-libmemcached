/**
 * Copyright (C) 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#if defined(USE_TLS) && USE_TLS

#pragma once

/* A wrapper around OpenSSL SSL_CTX to allow easy SSL use without directly
 * calling OpenSSL.*/
typedef struct memc_SSL_CTX memc_SSL_CTX;

/* A wrapper around OpenSSL SSL to allow easy SSL use without directly
 * calling OpenSSL.*/
typedef struct memcached_SSL memcached_SSL;

/**
 * SSL context configurations
 */
typedef struct memcached_ssl_context_config {
    char *cert_file;                /* Cert file name */
    char *key_file;                 /* Private key filename for cert_file */
    char *key_file_pass;            /* Optional password for key_file */
    char *ca_cert_file;
    char *ca_cert_dir;
    char *hostname;                 /* Required unless skip_hostname_verify/skip_cert_verify is set to true */
    char *protocols;
    char *ciphers;
    char *ciphersuites;
    int prefer_server_ciphers;
    int session_caching;
    int session_cache_size;
    int session_cache_timeout;
    bool skip_cert_verify;
    bool skip_hostname_verify;
} memcached_ssl_context_config;
#endif //USE_TLS
