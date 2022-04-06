/* -*- Mode: C; tab-width: 2; c-basic-offset: 2; indent-tabs-mode: nil -*- */
/**
 * What is a library without an example to show you how to use the library?
 * In this example we implement a simple memcached client with TLS.
 *
 * Usage:
 *  ./tls_client
 *  ./tls_client [host] [port]
 *  ./tls_client [host] [port] [cert_fullpath] [key_fullpath]
 */

#include <libmemcached/memcached.h>

int main(int argc, char *argv[]) {
    memcached_server_st *servers = NULL;
    memcached_st *memc;
    memcached_return rc;
    memc_ssl_context_error error;
    memcached_ssl_context_config config = {};
    char *host = "127.0.0.1";
    int port = 11211;
    char *cert_file = "/path/to/cert";
    char *key_file = "/path/to/key";
    char *key = "keystring";
    char *value = "keyvalue";
    char *returned_value;
    size_t vlen;

    if (argc >= 3) {

        host = argv[1];
        port = atoi(argv[2]);
        if (argc >= 5) {
            cert_file = argv[3];
            key_file = argv[4];
        }
    }

    // Create a memcached client instance
    memc = memcached_create(NULL);

    // Set SSL configurations, see all configurations in libmemcached-1.0/struct/tls.h
    config.cert_file = cert_file;
    config.key_file = key_file;
    config.skip_cert_verify = true;

    // Create SSL context
    memc_SSL_CTX *ssl_ctx = memcached_create_ssl_context(memc, &config, &error);
    if (ssl_ctx == NULL) {
        fprintf(stderr, "Failed to create SSL context: %s", memcached_ssl_context_get_error(error));
        exit(EXIT_FAILURE);
    }

    // Add servers
    servers = memcached_server_list_append(servers, host, port, &rc);
    memcached_server_push(memc, servers);

    // Set the SSL context to the memcached client
    rc = memcached_set_ssl_context(memc, ssl_ctx);
    if (rc != MEMCACHED_SUCCESS) {
        fprintf(stderr, "Failed to set SSL context: %s", memcached_strerror(NULL, rc));
        exit(EXIT_FAILURE);
    }

    rc = memcached_set(memc, key, strlen(key), value, strlen(value), (time_t) 0, (uint32_t) 0);
    if (rc == MEMCACHED_SUCCESS)
        fprintf(stderr, "Key '%s' stored successfully\n", key);
    else {
        fprintf(stderr, "Couldn't store key: %s\n", memcached_last_error_message(memc));
        exit(EXIT_FAILURE);
    }

    returned_value = memcached_get(memc, key, strlen(key), &vlen, (uint32_t) 0, &rc);
    if (rc == MEMCACHED_SUCCESS)
        fprintf(stderr, "Successfully retrieved key '%s', the value is: '%s'\n", key, returned_value);
    else {
        fprintf(stderr, "Couldn't retrieve key: %s\n", memcached_strerror(memc, rc));
        exit(EXIT_FAILURE);
    }

    free(returned_value);
    memcached_free(memc);

    return 0;
}