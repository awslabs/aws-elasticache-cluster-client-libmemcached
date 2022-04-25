/**
 * Copyright (C) 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#if defined(USE_TLS) && USE_TLS

#pragma once

/* A wrapper around OpenSSL SSL_CTX to allow easy SSL use without directly
 * calling OpenSSL.*/
typedef struct memcached_SSL_CTX memcached_SSL_CTX;

/* A wrapper around OpenSSL SSL to allow easy SSL use without directly
 * calling OpenSSL.*/
typedef struct memcached_SSL memcached_SSL;

/**
 * SSL context configurations.
 * The client's certificate and key file are only supported in PEM format.
 */
typedef struct memcached_ssl_context_config {
    char *cert_file;                /* Cert file name (PEM formatted)*/
    char *key_file;                 /* Private key filename for cert_file (PEM formatted)*/
    char *key_file_pass;            /* Optional password for key_file */
    char *ca_cert_file;
    char *ca_cert_dir;
    char *hostname;                 /* Required unless skip_hostname_verify is set to true */
    char *protocol;                 /* Enable only one of the TLS protocols: TLSv1.2 or TLSv1.3. If not set, both v1.2 and v1.3 are enabled. */
    char *ciphers;
    char *ciphersuites;
    bool prefer_server_ciphers;     /* When choosing a cipher, use the server's preferences instead of the client preferences. Default value: false. */
    bool skip_cert_verify;          /* Default value: false. */
    bool skip_hostname_verify;      /* Default value: false. */
} memcached_ssl_context_config;
#endif //USE_TLS
