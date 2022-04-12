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
 */

#include <mem_config.h>
#include <libtest/test.hpp>
#include "clients/utilities.h"
#include <libmemcached-1.0/memcached.h>
#include "tests/libmemcached-1.0/callback_counter.h"
#include <stdlib.h>

using namespace libtest;

char *cert_file = NULL;
char *key_file = NULL;
char *ssl_dir_full_path = NULL;
static const char *TLS_CERT_DIR = "/tests/libmemcached-1.0/tls/certs";
char *key = "foo";
char *value = "bar";
/*
  Test cases
*/


static test_return_t pre_ssl(memcached_st *)
{
  SKIP_IF(USE_TLS == 0);

  return TEST_SUCCESS;
}

/*
 * Test that the sasl authentication works. We cannot use the default
 * pool of servers, because that would require that all servers we want
 * to test supports SASL authentication, and that they use the default
 * creds.
 */

static bool init_ssl(memcached_st *memc) {
    return initialize_tls(memc, (char *)cert_file, (char *)key_file, NULL, true);
}

static test_return_t ssl_set_get_test(memcached_st *memc)
{
    size_t string_length;
    memcached_return_t rc;
    char *res_value;
    uint32_t flags;
    test_compare(true, init_ssl(memc));
    test_compare(MEMCACHED_SUCCESS, memcached_set(memc, key, strlen(key), value, strlen(value), (time_t)0, (uint32_t)0));
    res_value= memcached_get(memc, key, strlen(key), &string_length, &flags, &rc);
    test_compare(MEMCACHED_SUCCESS, rc);
    test_true(res_value);
    test_compare(strlen(value), string_length);
    if(strcmp(value, res_value))
    {
        return TEST_FAILURE;
    }
    test_compare(MEMCACHED_SUCCESS, memcached_delete(memc, key, strlen(key), 0));
    free(res_value);
    memcached_quit(memc);
    return TEST_SUCCESS;
}

static test_return_t ssl_connection_failure_test(memcached_st *memc)
{
    // We expect to get connection failure without initializing TLS
    test_compare(MEMCACHED_CONNECTION_FAILURE,
                 memcached_set(memc, key, strlen(key), value, strlen(value), (time_t)0, (uint32_t)0));
    return TEST_SUCCESS;
}

static test_return_t ssl_fail_with_udp_connection_test()
{
    memcached_st *memc = memcached_create(NULL);
    test_compare(true, init_ssl(memc));
    // TLS + UDP -> INVALID_ARGS
    memcached_return_t rc = memcached_behavior_set(memc, MEMCACHED_BEHAVIOR_USE_UDP, 1);
    test_true(rc == MEMCACHED_INVALID_ARGUMENTS);
    free(memc);
    return TEST_SUCCESS;
}

static test_return_t ssl_dynamic_tls_behavior_test(memcached_st *memc)
{
    // Enable TLS
    test_compare(true, init_ssl(memc));
    memc_SSL_CTX *ssl_ctx = memcached_get_ssl_context_copy(memc);
    test_true(ssl_ctx != NULL);
    test_compare(MEMCACHED_SUCCESS, memcached_set(memc, key, strlen(key), value, strlen(value), (time_t)0, (uint32_t)0));

    // Disable TLS
    test_compare(MEMCACHED_SUCCESS, memcached_behavior_set(memc, MEMCACHED_BEHAVIOR_USE_TLS, 0));
    test_compare(MEMCACHED_CONNECTION_FAILURE, memcached_set(memc, key, strlen(key), value, strlen(value), (time_t)0, (uint32_t)0));;

    // Enable TLS with the previous SSL context
    test_compare(MEMCACHED_SUCCESS, memcached_behavior_set(memc, MEMCACHED_BEHAVIOR_USE_TLS, 1));
    test_compare(MEMCACHED_SUCCESS, memcached_set_ssl_context(memc, ssl_ctx));
    test_compare(MEMCACHED_SUCCESS, memcached_set(memc, key, strlen(key), value, strlen(value), (time_t)0, (uint32_t)0));

    test_compare(MEMCACHED_SUCCESS, memcached_delete(memc, key, strlen(key), 0));
    memcached_quit(memc);
    return TEST_SUCCESS;
}

static test_return_t shared_ssl_ctx_test(memcached_st *memc)
{
    // Enable TLS
    test_compare(true, init_ssl(memc));
    test_compare(MEMCACHED_SUCCESS, memcached_set(memc, key, strlen(key), value, strlen(value), (time_t)0, (uint32_t)0));
    memc_SSL_CTX *ssl_ctx_get = memcached_get_ssl_context_copy(memc);
    test_true(ssl_ctx_get != NULL);

    // Clone client
    memcached_st *memc_clone= memcached_clone(NULL, memc);
    test_true(memc_clone);
    test_compare(MEMCACHED_SUCCESS, memcached_set(memc, key, strlen(key), value, strlen(value), (time_t)0, (uint32_t)0));

    // Test that both memcached instances are sharing the same SSL_CTX
    memc_SSL_CTX *ssl_ctx = memcached_get_ssl_context_copy(memc);
    memc_SSL_CTX *ssl_ctx_cloned = memcached_get_ssl_context_copy(memc_clone);
    test_true((ssl_ctx != NULL) && (ssl_ctx->ctx != NULL));
    test_true((ssl_ctx_cloned != NULL) && (ssl_ctx_cloned->ctx != NULL));
    test_true(ssl_ctx->ctx == ssl_ctx_cloned->ctx);

    // Test set with the cloned client
    test_compare(MEMCACHED_SUCCESS, memcached_set(memc_clone, key, strlen(key), value, strlen(value), (time_t)0, (uint32_t)0));

    // Delete the key on the original client before disabling TLS
    test_compare(MEMCACHED_SUCCESS, memcached_delete(memc, key, strlen(key), 0));
    // Disable TLS on the original client
    test_compare(MEMCACHED_SUCCESS, memcached_behavior_set(memc, MEMCACHED_BEHAVIOR_USE_TLS, 0));
    test_null(memcached_get_ssl_context_copy(memc));

    // Make sure the SSL_CTX wasn't freed
    test_true(ssl_ctx_cloned->ctx != NULL);

    // Test that executing set with the cloned client still succeed
    test_compare(MEMCACHED_SUCCESS, memcached_set(memc_clone, key, strlen(key), value, strlen(value), (time_t)0, (uint32_t)0));

    // Cleanup
    test_compare(MEMCACHED_SUCCESS, memcached_delete(memc_clone, key, strlen(key), 0));
    free(memc_clone);
    memcached_quit(memc);
    return TEST_SUCCESS;
}

static test_return_t ssl_no_blocking_io_no_replay_test(memcached_st *memc)
{
    unsigned int keys_count = 3;
    char *global_keys[keys_count];
    char *global_values[keys_count];
    size_t global_keys_length[keys_count];

    test_compare(MEMCACHED_SUCCESS, memcached_behavior_set(memc, MEMCACHED_BEHAVIOR_NO_BLOCK, 1));
    test_compare(MEMCACHED_SUCCESS, memcached_behavior_set(memc, MEMCACHED_BEHAVIOR_NOREPLY, 1));
    test_compare(true, init_ssl(memc));

    for (unsigned int i = 0; i < keys_count; i++) {
        std::string i_key = "foo" + std::to_string(i);
        std::string i_value = "bar" + std::to_string(i);
        global_keys[i] = (char *)i_key.c_str();
        global_values[i] = (char *)i_value.c_str();
        global_keys_length[i] = i_key.length();
        test_compare(MEMCACHED_SUCCESS, memcached_set(memc, global_keys[i], global_keys_length[i], global_values[i], global_keys_length[i], (time_t)0, (uint32_t)0));
    }

    test_compare(MEMCACHED_SUCCESS, memcached_mget(memc, global_keys, global_keys_length, keys_count));

    memcached_execute_fn callbacks[]= { &callback_counter };
    size_t counter= 0;
    test_compare(MEMCACHED_SUCCESS,
                 memcached_fetch_execute(memc, callbacks, (void *)&counter, 1));
    test_compare(counter, keys_count);
    for (unsigned int i = 0; i < keys_count; i++) {
        test_compare(MEMCACHED_SUCCESS, memcached_delete(memc, global_keys[i], global_keys_length[i], 0));
    }
    memcached_quit(memc);
    return TEST_SUCCESS;
}

test_st ssl_tests[]= {
        {"ssl_set_get_test", true, (test_callback_fn*)ssl_set_get_test },
        {"ssl_connection_failure_test", true, (test_callback_fn*)ssl_connection_failure_test },
        {"ssl_non_blocking_no_replay_test", true, (test_callback_fn*)ssl_no_blocking_io_no_replay_test },
        {"ssl_fail_with_udp_connection_test", true, (test_callback_fn*)ssl_fail_with_udp_connection_test },
        {"ssl_dynamic_tls_behavior_test", true, (test_callback_fn*)ssl_dynamic_tls_behavior_test },
        {"shared_ssl_ctx_test", true, (test_callback_fn*)shared_ssl_ctx_test },
        {0, 0, (test_callback_fn*)0}
};

collection_st collection[] ={
        {"ssl_tests", (test_callback_fn*)pre_ssl, 0, ssl_tests},
        {0, 0, 0, 0}
};

static char *get_realpath(char *path) {
    char *resolved_path = (char *)malloc(PATH_MAX);
    if (realpath(path, resolved_path) == NULL) {
        Error << "realpath failed to resolve SSL directory path " << path << ": " << strerror(errno) << "\n";
        free(resolved_path);
        return NULL;
    }
    return resolved_path;
}
static char * get_ssl_certs_dir(){
    std::stringstream buf;
    char * temp;
    char * pwd;
    if ((temp = getenv("srcdir")) && (pwd = getenv("PWD"))) {
        buf << pwd << "/" << temp << TLS_CERT_DIR;
        std::string s_path = buf.str();
        return get_realpath((char *)s_path.c_str());
    } else {
        Error << "Couldn't find TLS certificates directory.\n"
                 "You can set the TLS_CERT_FILE and TLS_KEY_FILE environment variables with full certificate paths.";
        return NULL;
    }
}

static const char* get_ssl_file(const char* env_var, const char* filename) {
    char *ssl_file;
    std::stringstream path_buf;
    if (env_var != NULL && (ssl_file = getenv(env_var))) {
        fprintf(stderr, "Got TLS certificate file from environment variable %s: %s\n", env_var, ssl_file);
        return get_realpath(ssl_file);
    } else {
        if (ssl_dir_full_path == NULL) {
            ssl_dir_full_path = get_ssl_certs_dir();
            if (ssl_dir_full_path == NULL) {
                Error << "Failed to get TLS directory\n";
                return NULL;
            }
        }
        path_buf << ssl_dir_full_path << "/" << filename;
        std::string s_path = path_buf.str();
        if(access(s_path.c_str(), F_OK) == 0) {
            // file exists
            ssl_file = (char *)malloc(s_path.length() + 1);
            std::copy(s_path.c_str(), s_path.c_str() + s_path.length() + 1, ssl_file);
            return ssl_file;
        } else {
            // file doesn't exist
            return NULL;
        }

    }
}


#include "tests/libmemcached_world.h"

static bool world_destroy_ssl(void *object)
{
    libmemcached_test_container_st *container= (libmemcached_test_container_st *)object;

    delete container;

    if (cert_file) {
        free(cert_file);
    }

    if (key_file) {
        free(key_file);
    }

    if (ssl_dir_full_path) {
        free(ssl_dir_full_path);
    }

    return TEST_SUCCESS;
}

void get_world(libtest::Framework* world)
{
    world->collections(collection);

    world->create((test_callback_create_fn*)world_create);
    world->destroy((test_callback_destroy_fn*)world_destroy_ssl);

    world->set_runner(new LibmemcachedRunner);

    cert_file = (char *)get_ssl_file("TLS_CERT_FILE", "memc-cert.pem");
    key_file = (char *)get_ssl_file("TLS_KEY_FILE", "memc-key.pem");

    if (cert_file == NULL || key_file == NULL) {
        Error << "Failed to get TLS key/cert file variables!\nSee tests/libmemcached-1.0/tls/README for more info";
        exit(EXIT_SKIP);
    }

    world->set_ssl_certs(cert_file, key_file);
}
