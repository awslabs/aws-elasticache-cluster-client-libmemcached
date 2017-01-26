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


#include <config.h>
#include<string.h>
#include <libtest/common.h>

namespace libtest {

  /*
   * This is the only available option to implement this because as of now both 'version' command
   * of HTTP API and '-V' command-line option return only X.Y.Z version without any information as
   * to whether it is plain open source or AWS Elasticache flavor of the engine.
   */
  bool server_supports_dynamic_mode(uint16_t port) {
    char cmd[100];
    FILE *fp;
    sprintf(cmd, "echo -n -e \"config get cluster\\r\\n\" | nc localhost %d", port);
    if ((fp = popen(cmd, "r")) == NULL) {
      // likely memcached (server) binary not present on the system
      return false;
    }
    char buf[100];
    bool result = true;
    if (fgets(buf, 100, fp) == NULL || strcmp(buf, "ERROR\r\n") == 0) {
      	result = false;
    }
    if(pclose(fp)) {
      fprintf(stderr, "pclose() exited with error");
    }
    return result;
  }


  void set_config(const char *config, uint16_t port, char *version)
  {
    int length = strlen(config) + strlen(version) + 2; //Add two for \r and \n
    char buffer[2000];
    sprintf(buffer, "\"config set cluster 0 %d\\r\\n%s\\r\\n%s\\r\\n\"", length, version, config);
    // To run for memcached 1.4.5, switch to this: sprintf(buffer, "\"set AmazonElastiCache:cluster 0 0 %d\\r\\n%s\\r\\n%s\\r\\n\"", length, version, config);
    char cmd[2500];
    sprintf(cmd, "echo -n -e %s | nc localhost %d >/dev/null", buffer, port);
    system(cmd);
  }

  test_return_t check_bad_config_with_no_newline(void *){
    const char* config = "1testcachehost.amazonaws.com|1.2.3.4|11211";
    memcached_server_st *server;
    server = parse_memcached_configuration((char *)config);
    test_true(server == NULL);
    return TEST_SUCCESS;
  }

  test_return_t check_bad_config_with_missing_pipe(void *){
    const char* config = "1\ntestcachehost.amazonaws.com|11211";
    memcached_server_st *server;
    server = parse_memcached_configuration((char *)config);
    test_true(server == NULL);
    return TEST_SUCCESS;
  }

  test_return_t check_bad_config_with_missing_pipe2(void *){
    const char* config = "1\ntestcachehost.amazonaws.com|1.2.3.411211";
    memcached_server_st *server;
    server = parse_memcached_configuration((char *)config);
    test_true(server == NULL);
    return TEST_SUCCESS;
  }

  test_return_t check_invalid_config(void *){
    const char* config = "xyz";
    memcached_server_st *server;
    server = parse_memcached_configuration((char *)config);
    test_true(server == NULL);
    return TEST_SUCCESS;
  }

  test_return_t check_1host_config(void *){
    const char* config = "1\ntestcachehost.amazonaws.com|1.2.3.4|11211";
    memcached_server_st *server;
    server = parse_memcached_configuration((char *)config);
    test_true(strcmp(server->hostname, "testcachehost.amazonaws.com") == 0);
    test_true(strcmp(server->ipaddress, "1.2.3.4") == 0);
    test_true(server->port == 11211);
    test_true(server->number_of_hosts == 1);
    free(server);
    return TEST_SUCCESS;
  }

  test_return_t check_emptyip_config(void *){
    const char* config = "1\ntestcachehost.amazonaws.com||11211";
    memcached_server_st *server;
    server = parse_memcached_configuration((char *)config);
    test_true(strcmp(server->hostname, "testcachehost.amazonaws.com") == 0);
    test_true(strcmp(server->ipaddress, "") == 0);
    test_true(server->port == 11211);
    test_true(server->number_of_hosts == 1);
    free(server);
    return TEST_SUCCESS;
  }

  test_return_t check_3host_config(void *){
    const char* config = "1\nhost1.amazon.com|1.2.3.4|11211 host2.amazon.com|2.2.3.4|11211 host3.amazon.com|3.2.3.4|11211";
    memcached_server_st *server;
    server = parse_memcached_configuration((char *)config);
    test_true(server->number_of_hosts == 3);
    test_true(strcmp(server[0].hostname, "host1.amazon.com") == 0);
    test_true(strcmp(server[0].ipaddress, "1.2.3.4") == 0);
    test_true(server[0].port == 11211);

    test_true(strcmp(server[1].hostname, "host2.amazon.com") == 0);
    test_true(strcmp(server[1].ipaddress, "2.2.3.4") == 0);
    test_true(server[1].port == 11211);

    test_true(strcmp(server[2].hostname, "host3.amazon.com") == 0);
    test_true(strcmp(server[2].ipaddress, "3.2.3.4") == 0);
    test_true(server[2].port == 11211);
    free(server);
    return TEST_SUCCESS;
  }

  test_return_t check_dynamic_behavior_set(void *){
    memcached_st *memc = memcached_create(NULL);;
    memcached_behavior_set(memc, MEMCACHED_BEHAVIOR_CLIENT_MODE, 1);
    test_true(memc->flags.client_mode == DYNAMIC_MODE);
    free(memc);
    return TEST_SUCCESS;
  }

  test_return_t check_static_behavior_set(void *){
    memcached_st *memc = memcached_create(NULL);;
    memcached_behavior_set(memc, MEMCACHED_BEHAVIOR_CLIENT_MODE, 0);
    test_true(memc->flags.client_mode == STATIC_MODE);
    free(memc);
    return TEST_SUCCESS;
  }

  test_return_t check_dynamic_behavior_get(void *){
    memcached_st *memc = memcached_create(NULL);;
    memcached_behavior_set(memc, MEMCACHED_BEHAVIOR_CLIENT_MODE, 1);
    test_true(memcached_behavior_get(memc, MEMCACHED_BEHAVIOR_CLIENT_MODE));
    free(memc);
    return TEST_SUCCESS;
  }

  test_return_t check_static_behavior_get(void *){
    memcached_st *memc = memcached_create(NULL);;
    memcached_behavior_set(memc, MEMCACHED_BEHAVIOR_CLIENT_MODE, 0);
    test_true(memcached_behavior_get(memc, MEMCACHED_BEHAVIOR_CLIENT_MODE) == 0);
    free(memc);
    return TEST_SUCCESS;
  }

  test_return_t check_default_static_mode(void *){
    memcached_st *memc = memcached_create(NULL);
    test_true(memc->flags.client_mode == UNDEFINED);
    free(memc);
    return TEST_SUCCESS;
  }

  test_return_t check_has_ipaddress_true(void *){
    memcached_server_st *server = NULL;
    memcached_return rc;
    server= memcached_server_list_append_with_ipaddress(server, "localhost", "10.61.120.162", 11211, &rc);
    test_true(has_memcached_server_ipaddress(server));
    free(server);
    return TEST_SUCCESS;
  }

  test_return_t check_has_ipaddress_false(void *){
    memcached_server_st *server = NULL;
    memcached_return rc;
    server= memcached_server_list_append(server, "localhost", 11211, &rc);
    test_true(!has_memcached_server_ipaddress(server));
    free(server);
    return TEST_SUCCESS;
  }

  test_return_t check_get_ipaddress(void *){
    memcached_server_st *server = NULL;
    memcached_return rc;
    server= memcached_server_list_append_with_ipaddress(server, "localhost", "10.61.120.162", 11211, &rc);
    test_true(strcmp(memcached_server_ipaddress(server), "10.61.120.162") == 0);
    free(server);
    return TEST_SUCCESS;
  }

  /**
   * Validate that UDP and DYNAMIC_MODE are not supported
   */
  test_return_t check_udp_dynamic_mode(void *)    
  {
    memcached_st *server = memcached_create(NULL);
    // dynamic mode + udp -> INVALID_ARGS
    memcached_return_t rc = memcached_behavior_set(server, MEMCACHED_BEHAVIOR_CLIENT_MODE, DYNAMIC_MODE);
    test_true(memcached_success(rc));
    rc = memcached_behavior_set(server, MEMCACHED_BEHAVIOR_USE_UDP, 1);
    test_true(rc == MEMCACHED_INVALID_ARGUMENTS);

    // static mode + udp -> SUCCESS
    rc = memcached_behavior_set(server, MEMCACHED_BEHAVIOR_CLIENT_MODE, STATIC_MODE);
    test_true(memcached_success(rc));
    rc = memcached_behavior_set(server, MEMCACHED_BEHAVIOR_USE_UDP, 1);
    test_true(rc == MEMCACHED_SUCCESS);

    // set UDP first, then DYNAMIC mode -> INVALID_ARGS
    rc = memcached_behavior_set(server, MEMCACHED_BEHAVIOR_USE_UDP, 1);
    test_true(memcached_success(rc));
    rc = memcached_behavior_set(server, MEMCACHED_BEHAVIOR_CLIENT_MODE, DYNAMIC_MODE);
    test_true(rc == MEMCACHED_INVALID_ARGUMENTS);

    free(server);
  }

  /*
   * Validate the polling frequency behavior setting
   */
  test_return_t check_polling_frequency(void *)
  {
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
