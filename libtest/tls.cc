/**
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

#if defined(USE_TLS) && USE_TLS

#include "tls.h"
#include <mem_config.h>
#include <string.h>
#include <libtest/common.h>

namespace libtest {

  /*
   * Validate the polling frequency behavior setting
   */
  test_return_t test_create_ssl_context(void *)
  {
    memcached_return rc;
    memc_ssl_context_error error;
    memcached_ssl_context_config config = {};

    // Check for env variables
    if (cert_file == NULL) {
        cert_file = getenv("TLS_CERT_FILE");
    }
    if (key_file == NULL) {
        key_file = getenv("TLS_KEY_FILE");
    }
    if (ca_file == NULL) {
        ca_file = getenv("TLS_CA_CERT_FILE");
    }
    skip_verify = skip_verify || getenv("TLS_SKIP_VERIFY");

    config.cert_file = cert_file;
    config.key_file = key_file;
    config.ca_cert_file = ca_file;
    config.skip_cert_verify = skip_verify;
    ssl_ctx = memcached_create_ssl_context(memc, &config, &error);
    if (ssl_ctx == NULL) {
        fprintf(stderr,memcached_ssl_context_get_error(error));
        return false;
    } else {
        fprintf(stderr,"Created SSL context successfully\n");
    }
    rc = memcached_set_ssl_context(memc, ssl_ctx);
    if (rc != MEMCACHED_SUCCESS) {
        fprintf(stderr, memcached_strerror(NULL, rc));
        return false;
    } else {
        fprintf(stderr,"Set SSL context finished successfully\n");
    }

    memc_SSL_CTX *memcached_create_ssl_context(const memcached_st *ptr, memcached_ssl_context_config *ctx_config, memc_ssl_context_error *error);

    memcached_st *server = memcached_create(NULL);
    memcached_return_t rc = memcached_behavior_set(server, MEMCACHED_BEHAVIOR_DYNAMIC_POLLING_THRESHOLD_SECS, 20);
    test_true(memcached_success(rc));
    uint64_t polling = memcached_behavior_get(server, MEMCACHED_BEHAVIOR_DYNAMIC_POLLING_THRESHOLD_SECS);
    test_compare(20, polling);

    rc = memcached_behavior_set(server, MEMCACHED_BEHAVIOR_DYNAMIC_POLLING_THRESHOLD_SECS, 0);
    test_true(rc == MEMCACHED_INVALID_ARGUMENTS);
    free(server);
  }


}

#endif // USE_TLS