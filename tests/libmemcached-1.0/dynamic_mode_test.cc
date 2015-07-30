
#include <config.h>

#include <cstdlib>
#include <climits>

#include <libtest/test.hpp>

#include <libmemcached-1.0/memcached.h>
#include <libmemcached/util.h>


using namespace libtest;

#include "tests/libmemcached-1.0/dynamic_mode_test.h"
#define LOCAL_IP "10.61.120.162"

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

  if(strcmp(val, expected_config)){
    return TEST_FAILURE;
  }

  free(val);
  free(server_list);

  return TEST_SUCCESS;
}


test_return_t remove_node_test(memcached_st *ptr)
{
  if(ptr->flags.client_mode != DYNAMIC_MODE)
  {
    return TEST_SKIPPED;
  }

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
  servers= memcached_server_list_append(servers, "localhost", 11221, &rc);
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
  if(ptr->flags.client_mode != DYNAMIC_MODE)
  {
    return TEST_SKIPPED;
  }

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
  servers= memcached_server_list_append(servers, "localhost", 11221, &rc);
  servers= memcached_server_list_append(servers, "localhost", 11222, &rc);
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
  if(ptr->flags.client_mode != DYNAMIC_MODE){
    return TEST_SKIPPED;
  }

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
  servers= memcached_server_list_append_with_ipaddress(servers, "localhost", LOCAL_IP, 11221, &rc);
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
  if(ptr->flags.client_mode != DYNAMIC_MODE)
  {
    return TEST_SKIPPED;
  }

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
