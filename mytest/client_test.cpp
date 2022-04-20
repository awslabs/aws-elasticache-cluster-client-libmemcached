#include <libmemcached/memcached.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
int main(int argc, char *argv[]) {
    memcached_server_st *servers = NULL;
    memcached_st *memc;
    memcached_return rc;
    memc_ssl_context_error ssl_rc;
    memcached_SSL_CTX *ssl_ctx;
    memcached_SSL_CTX *ssl_ctx2;
    memcached_ssl_context_config config = {};
    char *host = "127.0.0.1";
    int port = 11212;
    //char *cert_file = "/home/ec2-user/clion/aws-elasticache-cluster-client-libmemcached/mytest/ssl_client/redis.crt";
    //char *key_file = "/home/ec2-user/clion/aws-elasticache-cluster-client-libmemcached/mytest/ssl_client/redis.key";

    char *ca_cert_file = NULL;
    char *hostname = NULL;
    char *cert_file = NULL;
    char *key_file = NULL;
    const char *key = "keystring";
    const char *value = "keyvalue";
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

    // Set SSL configurations, see all configurations in libmemcached-1.0/struct/tls.h
    config.cert_file = cert_file;
    config.key_file = key_file;
    config.ca_cert_file = ca_cert_file;
    config.hostname = hostname;
    config.skip_cert_verify = false;
    config.skip_hostname_verify = false;


    // Create and set  SSL context
    memcached_behavior_set(memc, MEMCACHED_BEHAVIOR_USE_TLS, 1);
    ssl_rc = memcached_create_and_set_ssl_context(memc, &config);
    if (ssl_rc != MEMCACHED_SSL_CTX_SUCCESS) {
        fprintf(stderr, "Failed to create SSL context: %s", memcached_ssl_context_get_error(ssl_rc));
        exit(EXIT_FAILURE);
    }
    /*
    if (rc != MEMCACHED_SUCCESS) {
        fprintf(stderr, "Failed to create SSL context: %s", memcached_strerror(NULL, rc));
        exit(EXIT_FAILURE);
    } */

    // Add servers
    servers = memcached_server_list_append(servers, host, port, &rc);
    memcached_server_push(memc, servers);
    memcached_st *memc_clone= memcached_clone(NULL, memc);

    ssl_ctx = memcached_get_ssl_context_copy(memc);
    if (ssl_ctx == NULL) {
        fprintf(stderr, "Failed to get SSL context");
    }
    ssl_ctx2 = memcached_get_ssl_context_copy(memc_clone);
    if (ssl_ctx2 == NULL) {
        fprintf(stderr, "Failed to get SSL context from clone");
    }


    /*
    // Set the SSL context to the memcached client

    rc = memcached_set_ssl_context(memc, ssl_ctx);
    if (rc != MEMCACHED_SUCCESS) {
        fprintf(stderr, "Failed to set SSL context: %s", memcached_strerror(NULL, rc));
        exit(EXIT_FAILURE);
    }
*/
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

    rc = memcached_set(memc_clone, key, strlen(key), value, strlen(value), (time_t) 0, (uint32_t) 0);
    if (rc == MEMCACHED_SUCCESS)
        fprintf(stderr, "Key '%s' stored successfully in memc_clone\n", key);
    else {
        fprintf(stderr, "Couldn't store key in memc_clone: %s\n", memcached_last_error_message(memc_clone));
        exit(EXIT_FAILURE);
    }


    returned_value = memcached_get(memc_clone, key, strlen(key), &vlen, (uint32_t) 0, &rc);
    if (rc == MEMCACHED_SUCCESS)
        fprintf(stderr, "Successfully retrieved key from memc_clone'%s', the value is: '%s'\n", key, returned_value);
    else {
        fprintf(stderr, "Couldn't retrieve key from memc_clone: %s\n", memcached_strerror(memc_clone, rc));
        exit(EXIT_FAILURE);
    }

    rc = memcached_behavior_set(memc, MEMCACHED_BEHAVIOR_USE_TLS, 0);

    returned_value = memcached_get(memc, key, strlen(key), &vlen, (uint32_t) 0, &rc);
    if (rc == MEMCACHED_SUCCESS)
        fprintf(stderr, " retrieved key without TLS '%s', the value is: '%s'\n", key, returned_value);
    else {
        fprintf(stderr, "Successfully couldn't retrieve key without TLS: %s\n", memcached_strerror(memc, rc));
    }

    //rc = memcached_behavior_set(memc, MEMCACHED_BEHAVIOR_USE_TLS, 1);

    // Set the prev SSL context to the memcached client
    if (ssl_ctx == NULL)
    {
        fprintf(stderr, "ssl_ctx is null\n");
        exit(1);
    }
/*
    rc = memcached_set_ssl_context(memc, ssl_ctx);
    if (rc != MEMCACHED_SUCCESS) {
        fprintf(stderr, "Failed to set SSL context: %s\n", memcached_strerror(NULL, rc));
        exit(EXIT_FAILURE);
    }
*/
    returned_value = memcached_get(memc_clone, key, strlen(key), &vlen, (uint32_t) 0, &rc);
    if (rc == MEMCACHED_SUCCESS)
        fprintf(stderr, "Successfully retrieved key from memc_clone%s', the value is: '%s'\n", key, returned_value);
    else {
        fprintf(stderr, "Couldn't retrieve key from memc_clone: %s\n", memcached_strerror(memc_clone, rc));
        exit(EXIT_FAILURE);
    }

    /*
    char *output;
    rc = memcached_ssl_get_server_certs((memcached_instance_st*)memcached_server_instance_by_position(memc, 0), output);
    if (rc == MEMCACHED_SUCCESS) {
        fprintf(stderr, "Successfully retrieved server's certs, the value is: '%s'\n", output);
    } else {
        fprintf(stderr, "Couldn't retrieve server's certs: %s\n", memcached_strerror(memc_clone, rc));
        exit(EXIT_FAILURE);
    }
    */

    free(returned_value);
    memcached_free(memc);
    memcached_free(memc_clone);


    return 0;
}