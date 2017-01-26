
#include <config.h>

#include <cstdlib>
#include <climits>

#include <sys/types.h>
#include <ifaddrs.h>
#include <netinet/in.h> 
#include <arpa/inet.h>

#include <libtest/test.hpp>
#include <libtest/dynamic_mode.h>

#include <libmemcached-1.0/memcached.h>
#include <libmemcached/util.h>

#include "tests/libmemcached-1.0/dynamic_mode_test.h"

using namespace libtest;

/**
 * Integration-style tests for dynamic client mode (aka Auto Discovery, see:
 * http://docs.aws.amazon.com/AmazonElastiCache/latest/UserGuide/AutoDiscovery.html)
 *
 * This test suite is not configured to run as part of 'make test' target because it depends on 
 * modified memcached server version, the kind that is run on AWS ElastiCache nodes, to be present
 * installed on the system. If this required binary is missing the tests that need it will be skipped.
 *
 * To run:
 *
 *   ./configure
 *   make
 *   ./tests/dynamic_mode_test
 */

static char* _get_addr_by_ifa_name_for_ipv(const char* ifa_name_str, bool ipv6)
{
  char *res = NULL;
  struct ifaddrs * ifa=NULL;
  getifaddrs(&ifa);
  for (struct ifaddrs * cur_ifa = ifa; cur_ifa != NULL; cur_ifa = cur_ifa->ifa_next) 
  {
    if (cur_ifa->ifa_addr == NULL) 
    {
      continue;
    }
    if (ifa_name_str != NULL &&
        strcmp(ifa_name_str, cur_ifa->ifa_name) == 0 &&
        cur_ifa->ifa_addr->sa_family == (ipv6 ? AF_INET6 : AF_INET)) 
    {
      void *sin_addr;
      if (ipv6) 
      {
        sin_addr = &((struct sockaddr_in6 *)cur_ifa->ifa_addr)->sin6_addr;
      } else
      {
	sin_addr = &((struct sockaddr_in *)cur_ifa->ifa_addr)->sin_addr;
      }
      int addr_len = ipv6 ? INET6_ADDRSTRLEN : INET_ADDRSTRLEN;
      res = (char*) malloc(addr_len * sizeof(char));
      inet_ntop(ipv6 ? AF_INET6 : AF_INET, sin_addr, res, addr_len);
      break;
    }
  }
  if (ifa != NULL)
  {
    freeifaddrs(ifa);
  }
  return res;
}

/*
 * Get a null-terminated string representing the IP address (e.g. "172.31.22.18")
 * assigned to a local network interface with a given name (e.g. "eth0"). 
 * If an IPv4 address exists for the interface it will be returned, otherwise falls 
 * back to IPv6.
 */
static char* _get_private_ip_of_local_netw_interface() {
  char *res[4] = {
	_get_addr_by_ifa_name_for_ipv("eth0", false),
	_get_addr_by_ifa_name_for_ipv("wlan0", false),
	_get_addr_by_ifa_name_for_ipv("eth0", true),
	_get_addr_by_ifa_name_for_ipv("wlan0", true)
  };
  for (int i = 0; i < 4; i++) {
    if (res[i] != NULL) {
      return res[i];
    }
  }
  return NULL;
}

static char * build_server_list(memcached_server_st *servers, uint32_t count)
{
  char *buffer = (char *)malloc(2000);
  buffer[0] = '\0';
  for(uint32_t i=0; i<count; i++)
  {
    memcached_server_st m_server = servers[i];
    strcat(buffer, "localhost|127.0.0.1|");
    char port[6];
    sprintf(port,"%d ", m_server.port);
    strcat(buffer, port);
  }

  return buffer;
}


test_return_t config_get_test(memcached_st *ptr)
{
  uint32_t flags;
  size_t value_length;
  memcached_return rc;
  char *server_list = build_server_list(ptr->servers, memcached_server_list_count(ptr->servers));
  set_config(server_list, ptr->servers[0].port, "1");
  char expected_config[2000];
  sprintf(expected_config, "1\r\n%s", server_list);
  char *val = memcached_config_get(ptr->servers, ptr, &value_length, &flags, &rc);

  if (val == NULL || strcmp(val, expected_config)) 
  {
    return TEST_FAILURE;
  }

  free(val);
  free(server_list);

  return TEST_SUCCESS;
}


test_return_t remove_node_test(memcached_st *ptr)
{
  char *original_server_list = build_server_list(ptr->servers, memcached_server_list_count(ptr->servers));

  memcached_server_st *servers = NULL;
  memcached_st *memc;
  memcached_return rc;
  size_t value_length;
  uint32_t flags;

  char *key= "keystring";
  char *value= "keyvalue";
  memc= memcached_create(NULL);
  memcached_behavior_set(memc, MEMCACHED_BEHAVIOR_CLIENT_MODE, DYNAMIC_MODE);

  rc= memcached_server_push(memc, ptr->configserver);

  if (rc != MEMCACHED_SUCCESS)
  {
    return TEST_FAILURE;
  }

  rc= memcached_set(memc, key, strlen(key), value, strlen(value), (time_t)0, (uint32_t)0);

  if (rc != MEMCACHED_SUCCESS)
    return TEST_FAILURE;

  char *result = memcached_get(memc, key, strlen(key), &value_length, &flags, &rc);
  if(strcmp(value, result))
  {
    return TEST_FAILURE;
  }
  free(result);
  servers= memcached_server_list_append(servers, ptr->servers[0].hostname, ptr->servers[0].port, &rc);
  notify_server_list_update(memc, servers);

  rc= memcached_set(memc, key, strlen(key), value, strlen(value), (time_t)0, (uint32_t)0);

  if (rc != MEMCACHED_SUCCESS)
    return TEST_FAILURE;

  result = memcached_get(memc, key, strlen(key), &value_length, &flags, &rc);
  if(strcmp(value, result))
  {
    return TEST_FAILURE;
  }
  free(result);
  memcached_server_free(servers);
  memcached_free(memc);
  set_config(original_server_list, ptr->servers[0].port, "1");
  free(original_server_list);

  return TEST_SUCCESS;
}

test_return_t add_node_test(memcached_st *ptr)
{
  char *original_server_list = build_server_list(ptr->servers, memcached_server_list_count(ptr->servers));

  memcached_server_st *servers = NULL;
  memcached_st *memc;
  memcached_return rc;
  size_t value_length;
  uint32_t flags;

  char *key= "keystring";
  char *value= "keyvalue";
  memc= memcached_create(NULL);
  memcached_behavior_set(memc, MEMCACHED_BEHAVIOR_CLIENT_MODE, DYNAMIC_MODE);

  char *config = build_server_list(ptr->servers, 1);
  set_config(config, ptr->servers[0].port, "1");
  free(config);

  rc= memcached_server_push(memc, ptr->configserver);
  
  servers= memcached_server_list_append(servers, ptr->servers[0].hostname, ptr->servers[0].port, &rc);
  notify_server_list_update(memc, servers);

  if (rc != MEMCACHED_SUCCESS)
  {
    return TEST_FAILURE;
  }

  rc= memcached_set(memc, key, strlen(key), value, strlen(value), (time_t)0, (uint32_t)0);

  if (rc != MEMCACHED_SUCCESS)
    return TEST_FAILURE;

  char *result = memcached_get(memc, key, strlen(key), &value_length, &flags, &rc);
  if(strcmp(value, result))
  {
    return TEST_FAILURE;
  }
  free(result);
  servers= memcached_server_list_append(servers, ptr->servers[0].hostname, ptr->servers[0].port, &rc);
  servers= memcached_server_list_append(servers, ptr->servers[1].hostname, ptr->servers[1].port, &rc);
  notify_server_list_update(memc, servers);

  rc= memcached_set(memc, key, strlen(key), value, strlen(value), (time_t)0, (uint32_t)0);

  if (rc != MEMCACHED_SUCCESS)
    return TEST_FAILURE;

  result = memcached_get(memc, key, strlen(key), &value_length, &flags, &rc);
  if(strcmp(value, result))
  {
    return TEST_FAILURE;
  }
  free(result);
  memcached_server_free(servers);
  memcached_free(memc);
  set_config(original_server_list, ptr->servers[0].port, "1");
  free(original_server_list);

  return TEST_SUCCESS;
}

test_return_t replace_node_test(memcached_st *ptr)
{
  char *original_server_list = build_server_list(ptr->servers, memcached_server_list_count(ptr->servers));

  memcached_server_st *servers = NULL;
  memcached_st *memc;
  memcached_return rc;
  size_t value_length;
  uint32_t flags;

  char *key= "keystring";
  char *value= "keyvalue";
  memc= memcached_create(NULL);
  memcached_behavior_set(memc, MEMCACHED_BEHAVIOR_CLIENT_MODE, DYNAMIC_MODE);

  char *config = build_server_list(ptr->servers, 1);
  set_config(config, ptr->servers[0].port, "1");
  free(config);

  rc= memcached_server_push(memc, ptr->configserver);

  if (rc != MEMCACHED_SUCCESS)
  {
    return TEST_FAILURE;
  }

  rc= memcached_set(memc, key, strlen(key), value, strlen(value), (time_t)0, (uint32_t)0);

  if (rc != MEMCACHED_SUCCESS)
    return TEST_FAILURE;

  char *result = memcached_get(memc, key, strlen(key), &value_length, &flags, &rc);
  if(strcmp(value, result))
  {
    return TEST_FAILURE;
  }
  free(result);
  const char* local_ip = _get_private_ip_of_local_netw_interface();
  if (local_ip == NULL) 
  {
    return TEST_SKIPPED;
  }
  servers= memcached_server_list_append_with_ipaddress(servers, "localhost", local_ip, ptr->servers[0].port, &rc);
  notify_server_list_update(memc, servers);

  rc= memcached_set(memc, key, strlen(key), value, strlen(value), (time_t)0, (uint32_t)0);

  if (rc != MEMCACHED_SUCCESS)
    return TEST_FAILURE;

  result = memcached_get(memc, key, strlen(key), &value_length, &flags, &rc);
  if(strcmp(value, result))
  {
    return TEST_FAILURE;
  }
  free(result);
  memcached_server_free(servers);
  memcached_free(memc);
  set_config(original_server_list, ptr->servers[0].port, "1");

  free(original_server_list);

  return TEST_SUCCESS;
}

/**
 * Verify that polling occurs during the periodic interval
 */
test_return_t polling_test(memcached_st *ptr)
{
  char *original_server_list = build_server_list(ptr->servers, memcached_server_list_count(ptr->servers));

  memcached_server_st *servers = NULL;
  memcached_st *memc;
  memcached_return rc;

  memc= memcached_create(NULL);
  memcached_behavior_set(memc, MEMCACHED_BEHAVIOR_CLIENT_MODE, DYNAMIC_MODE);

  // Set the polling threshold
  memc->polling.threshold_secs = 1;

  char *config = build_server_list(ptr->servers, 1);
  uint32_t config_version = 1;
  char config_version_str[5];
  sprintf(config_version_str, "%d", config_version);
  set_config(config, ptr->servers[0].port, config_version_str);
  free(config);

  rc= memcached_server_push(memc, ptr->configserver);

  if (rc != MEMCACHED_SUCCESS)
  {
    return TEST_FAILURE;
  }

  // now iterate for 10s, sleeping 1s between each operation
  // this ensures 10 polling cycles to retrieve configuration
  // change the config every 2 seconds so 4 config changes
  int idx;
  for (idx = 0; idx < 10; idx++)
  {
    char *key = (char*) malloc(sizeof(char)*10);
    sprintf(key, "key-%04d", idx);
    char *value = (char*) malloc(sizeof(char)*10);
    sprintf(value, "val-%04d", idx);
    
    rc= memcached_set(memc, key, strlen(key), value, strlen(value), (time_t)0, (uint32_t)0);

    if (rc != MEMCACHED_SUCCESS)
      return TEST_FAILURE;

    size_t value_length;
    uint32_t flags;
    char *result = memcached_get(memc, key, strlen(key), &value_length, &flags, &rc);
    if(strcmp(value, result))
    {
      return TEST_FAILURE;
    }
    free(result);

    if (idx % 2 == 0)
    {
      // on even iterations update the server configuration
      // for updating the configuration, simply change the config version number
      // leaving the other integration tests to verify the actual notify_server_list_update
      // function.
      config = build_server_list(ptr->servers, 1);
      config_version++;
      sprintf(config_version_str, "%d", config_version);
      set_config(config, ptr->servers[0].port, config_version_str);
      free(config);
    }
    
    int iteration_secs = 1;
    // fprintf(stderr, "Sleeping for %d seconds before trying again\n", iteration_secs);
    sleep(iteration_secs);

    free(key);
    free(value);
  }

  // CLEANUP
  memcached_server_free(servers);
  memcached_free(memc);
  set_config(original_server_list, ptr->servers[0].port, "1");
  free(original_server_list);

  return TEST_SUCCESS;
}



#include <config.h>
#include <libtest/test.hpp>

#include "tests/basic.h"
#include "tests/debug.h"
#include "tests/deprecated.h"
#include "tests/error_conditions.h"
#include "tests/exist.h"
#include "tests/ketama.h"
#include "tests/namespace.h"
#include "tests/libmemcached-1.0/dump.h"
#include "tests/libmemcached-1.0/dynamic_mode_test.h"
#include "tests/libmemcached-1.0/generate.h"
#include "tests/libmemcached-1.0/haldenbrand.h"
#include "tests/libmemcached-1.0/parser.h"
#include "tests/libmemcached-1.0/stat.h"
#include "tests/touch.h"
#include "tests/callbacks.h"
#include "tests/pool.h"
#include "tests/print.h"
#include "tests/replication.h"
#include "tests/server_add.h"
#include "tests/virtual_buckets.h"

#include "tests/libmemcached-1.0/setup_and_teardowns.h"


#include "tests/libmemcached-1.0/mem_functions.h"
#include "tests/libmemcached-1.0/encoding_key.h"

#include "tests/libmemcached_world.h"

#include "tests/libmemcached-1.0/dynamic_mode_test.h"

void get_world(Framework *world)
{
  world->servers().set_servers_to_run(2);
  world->collections(collection);

  world->create((test_callback_create_fn*)world_create);
  world->destroy((test_callback_destroy_fn*)world_destroy);

  world->set_runner(new LibmemcachedRunner);

  //TODO remove coment or move to runner.h or, even better, CR now that I've found a way to work around it
  /*
   * Cannot do that because initializing a tests client in the framework is done through
   * memcached_clone() which eventually calls memcached_server_push() with source client's configserver 
   * (which also happens to be null since source client object is initialized through '--server' options string)
   * losing information about the rest of the servers. Even if we modified that behavior to fall back to calling
   * memcached_server_push() with the full list of servers from the source client, get_server_list_if_dynamic_mode()
   * would have only picked the first one assuming it is the config endpoint and discarded the rest.
   * In this test we need information about the full list of servers in order to call config_set() on the
   * config endpoint.
   */
  world->servers().set_client_mode(DYNAMIC_MODE);
}
