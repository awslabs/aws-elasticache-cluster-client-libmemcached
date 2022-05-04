/* -*- Mode: C; tab-width: 2; c-basic-offset: 2; indent-tabs-mode: nil -*- */
/**
 * What is a library without an example to show you how to use the library?
 * In this example we implement a simple memcached client with TLS.
 *
 * Usage:
 *  ./tls_client
 *  ./tls_client [host] [port]
 *  ./tls_client [host] [port] [cert_fullpath] [key_fullpath]
 *  ./tls_client [host] [port] [cert_fullpath] [key_fullpath] [ca_cert_fullpath]
 *  ./tls_client [host] [port] [cert_fullpath] [key_fullpath] [ca_cert_fullpath] [hostname]
 */

#include <libmemcached/memcached.h>

int main(int argc, char *argv[]) {
    memcached_server_st *servers = NULL;
    memcached_st *memc;
    memcached_return rc;
    memc_ssl_context_error ssl_ctx_rc;
    memcached_ssl_context_config config = {};
    char *host = "127.0.0.1";
    int port = 11211;
    char *cert_file = NULL;
    char *key_file = NULL;
    char *ca_cert_file = NULL;
    char *hostname = NULL;
    char *key = "keystring";
    char *value = "keyvalue";
    char *returned_value;
    size_t vlen;

    if (argc >= 3) {
        host = argv[1];
        port = atoi(argv[2]);
        fprintf(stderr, "host: %s, port: %d\n", host, port);
        if (argc >= 5) {
            cert_file = argv[3];
            key_file = argv[4];
            fprintf(stderr, "cert_file: %s, key_file: %s\n", cert_file, key_file);
        }
        if (argc >= 6) {
            ca_cert_file = argv[5];
            fprintf(stderr, "ca_cert_file: %s,\n", ca_cert_file);
        }
        if (argc >= 7) {
            hostname = argv[6];
            fprintf(stderr, "hostname: %s,\n", hostname);
        }

    }

    // Create a memcached client instance
    memc = memcached_create(NULL);

    // Add servers
    servers = memcached_server_list_append(servers, host, port, &rc);
    memcached_server_push(memc, servers);

    // Set SSL configurations, see all configurations in libmemcached-1.0/struct/tls.h
    config.cert_file = cert_file;
    config.key_file = key_file;
    config.ca_cert_file = ca_cert_file;
    config.hostname = hostname;
    config.skip_cert_verify = false;
    config.skip_hostname_verify = false;

    // Set TLS behavior to true
    memcached_behavior_set(memc, MEMCACHED_BEHAVIOR_USE_TLS, 1);

    // Create and set SSL context
    ssl_ctx_rc = memcached_create_and_set_ssl_context(memc, &config);
    if (ssl_ctx_rc != MEMCACHED_SSL_CTX_SUCCESS) {
        fprintf(stderr, "Failed to create/set SSL context: %s", memcached_ssl_context_get_error(ssl_ctx_rc));
        exit(EXIT_FAILURE);
    }

    // Test set and get
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

    // Clone client
    memcached_st *memc_clone= memcached_clone(NULL, memc);

    // Test TLS set and get with the cloned client
    rc = memcached_set(memc_clone, key, strlen(key), value, strlen(value), (time_t) 0, (uint32_t) 0);
    if (rc == MEMCACHED_SUCCESS)
        fprintf(stderr, "Key '%s' stored successfully with memc_clone client\n", key);
    else {
        fprintf(stderr, "Couldn't store key with memc_clone client: %s\n", memcached_last_error_message(memc_clone));
        exit(EXIT_FAILURE);
    }

    returned_value = memcached_get(memc_clone, key, strlen(key), &vlen, (uint32_t) 0, &rc);
    if (rc == MEMCACHED_SUCCESS)
        fprintf(stderr, "Successfully retrieved key '%s' with memc_clone client, the value is: '%s'\n", key, returned_value);
    else {
        fprintf(stderr, "Couldn't retrieve key with memc_clone client: %s\n", memcached_strerror(memc_clone, rc));
        exit(EXIT_FAILURE);
    }

    // Cleanup
    free(returned_value);
    memcached_free(memc);
    memcached_free(memc_clone);

    return 0;
}