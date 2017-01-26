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



#pragma once

namespace libtest {

  /*
   * Check if the local memcached server process running on a specified port supports
   * Elasticache Auto Discovery -related comands.    
   */ 
  bool server_supports_dynamic_mode(uint16_t port);

  void set_config(const char *config, uint16_t port, char *version);

  test_return_t  check_bad_config_with_no_newline(void *);

  test_return_t check_bad_config_with_missing_pipe(void *);

  test_return_t check_bad_config_with_missing_pipe2(void *);

  test_return_t check_invalid_config(void *);

  test_return_t check_1host_config(void *);

  test_return_t check_emptyip_config(void *);

  test_return_t check_3host_config(void *);

  test_return_t check_dynamic_behavior_set(void *);

  test_return_t check_static_behavior_set(void *);

  test_return_t check_default_static_mode(void *);

  test_return_t check_dynamic_behavior_get(void *);

  test_return_t check_static_behavior_get(void *);

  test_return_t check_has_ipaddress_true(void *);

  test_return_t check_has_ipaddress_false(void *);

  test_return_t check_get_ipaddress(void *);
}
