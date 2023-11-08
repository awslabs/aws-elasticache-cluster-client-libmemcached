/*  vim:expandtab:shiftwidth=2:tabstop=2:smarttab:
 * 
 *  Libmemcached library
 *
 *  Copyright (C) 2011 Data Differential, http://datadifferential.com/
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are
 *  met:
 *
 *      * Redistributions of source code must retain the above copyright
 *  notice, this list of conditions and the following disclaimer.
 *
 *      * Redistributions in binary form must reproduce the above
 *  copyright notice, this list of conditions and the following disclaimer
 *  in the documentation and/or other materials provided with the
 *  distribution.
 *
 *      * The names of its contributors may not be used to endorse or
 *  promote products derived from this software without specific prior
 *  written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *
 * Portions Copyright 2012-2015 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in
 * compliance with the License. A copy of the License is located at
 *
 *    http://aws.amazon.com/apache2.0/
 *
 * or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

#pragma once

enum memcached_return_t {
  MEMCACHED_SUCCESS,
  MEMCACHED_FAILURE,
  MEMCACHED_HOST_LOOKUP_FAILURE, // getaddrinfo() and getnameinfo() only
  MEMCACHED_CONNECTION_FAILURE,
  MEMCACHED_CONNECTION_BIND_FAILURE,  // DEPRECATED, see MEMCACHED_HOST_LOOKUP_FAILURE
  MEMCACHED_WRITE_FAILURE,
  MEMCACHED_READ_FAILURE,
  MEMCACHED_UNKNOWN_READ_FAILURE,
  MEMCACHED_PROTOCOL_ERROR,
  MEMCACHED_CLIENT_ERROR,
  MEMCACHED_SERVER_ERROR, // Server returns "SERVER_ERROR"
  MEMCACHED_ERROR, // Server returns "ERROR"
  MEMCACHED_DATA_EXISTS,
  MEMCACHED_DATA_DOES_NOT_EXIST,
  MEMCACHED_NOTSTORED,
  MEMCACHED_STORED,
  MEMCACHED_NOTFOUND,
  MEMCACHED_MEMORY_ALLOCATION_FAILURE,
  MEMCACHED_PARTIAL_READ,
  MEMCACHED_SOME_ERRORS,
  MEMCACHED_NO_SERVERS,
  MEMCACHED_END,
  MEMCACHED_DELETED,
  MEMCACHED_VALUE,
  MEMCACHED_STAT,
  MEMCACHED_ITEM,
  MEMCACHED_ERRNO,
  MEMCACHED_FAIL_UNIX_SOCKET, // DEPRECATED
  MEMCACHED_NOT_SUPPORTED,
  MEMCACHED_NO_KEY_PROVIDED, /* Deprecated. Use MEMCACHED_BAD_KEY_PROVIDED! */
  MEMCACHED_FETCH_NOTFINISHED,
  MEMCACHED_TIMEOUT,
  MEMCACHED_BUFFERED,
  MEMCACHED_BAD_KEY_PROVIDED,
  MEMCACHED_INVALID_HOST_PROTOCOL,
  MEMCACHED_SERVER_MARKED_DEAD,
  MEMCACHED_UNKNOWN_STAT_KEY,
  MEMCACHED_E2BIG,
  MEMCACHED_INVALID_ARGUMENTS,
  MEMCACHED_KEY_TOO_BIG,
  MEMCACHED_AUTH_PROBLEM,
  MEMCACHED_AUTH_FAILURE,
  MEMCACHED_AUTH_CONTINUE,
  MEMCACHED_PARSE_ERROR,
  MEMCACHED_PARSE_USER_ERROR,
  MEMCACHED_DEPRECATED,
  MEMCACHED_IN_PROGRESS,
  MEMCACHED_SERVER_TEMPORARILY_DISABLED,
  MEMCACHED_SERVER_MEMORY_ALLOCATION_FAILURE,
  MEMCACHED_NO_CONFIG_SERVER,
  MEMCACHED_TLS_ERROR,
  MEMCACHED_TLS_CONNECTION_ERROR,
  MEMCACHED_MAXIMUM_RETURN, /* Always add new error code before */
  MEMCACHED_CONNECTION_SOCKET_CREATE_FAILURE= MEMCACHED_ERROR
};

#ifndef __cplusplus
typedef enum memcached_return_t memcached_return_t;
#endif

enum memc_ssl_context_error {
    MEMCACHED_SSL_CTX_SUCCESS = 0,                      /* No Error */
    MEMCACHED_SSL_INVALID_ARGUMENTS,                    /* Invalid function arguments */
    MEMCACHED_SSL_MEMORY_ALLOCATION_FAILURE,            /* Failed to allocate memory */
    MEMCACHED_SSL_CTX_CREATE_FAILED,                    /* Failed to create OpenSSL SSL_CTX */
    MEMCACHED_SSL_CTX_HOSTNAME_REQUIRED,                /* Hostname (CN) is required unless skip_hostname_verify is set to true */
    MEMCACHED_SSL_CTX_CA_CERT_LOAD_FAILED,              /* Failed to load CA Certificate or CA Path */
    MEMCACHED_SSL_CTX_CLIENT_CERT_LOAD_FAILED,          /* Failed to load client certificate */
    MEMCACHED_SSL_CTX_PRIVATE_KEY_LOAD_FAILED,          /* Failed to load private key */
    MEMCACHED_SSL_CTX_INVALID_PROTOCOL,                 /* Invalid TLS protocol was passed */
    MEMCACHED_SSL_CTX_CIPHERS_LOAD_FAILED,              /* Failed to configure ciphers */
    MEMCACHED_SSL_CTX_CIPHERSUITES_LOAD_FAILED,         /* Failed to configure ciphersuites */
    MEMCACHED_SSL_CTX_PREFER_SERVER_CIPHER_LOAD_FAILED, /* Failed to configure the server's cipher preferences*/
    MEMCACHED_SSL_CTX_PRIVATE_KEY_MISMATCH              /* Private key does not match the public certificate */
};
#ifndef __cplusplus
typedef enum memc_ssl_context_error memc_ssl_context_error;
#endif