/*  vim:expandtab:shiftwidth=2:tabstop=2:smarttab:
 * 
 *  Libmemcached library
 *
 *  Copyright (C) 2011 Data Differential, http://datadifferential.com/
 *  Copyright (C) 2006-2010 Brian Aker All rights reserved.
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
 * Portions Copyright (C) 2012-2012 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Amazon Software License (the "License"). You may not use this
 * file except in compliance with the License. A copy of the License is located at
 *  http://aws.amazon.com/asl/
 * or in the "license" file accompanying this file. This file is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, express or
 * implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <libmemcached/common.h>
#include <cmath>
#include <sys/time.h>

/* Protoypes (static) */
static memcached_return_t update_continuum(memcached_st *ptr);

static int compare_servers(const void *p1, const void *p2)
{
  memcached_server_instance_st a= (memcached_server_instance_st)p1;
  memcached_server_instance_st b= (memcached_server_instance_st)p2;

  int return_value= strcmp(a->hostname, b->hostname);

  if (return_value == 0)
  {
    return_value= (int) (a->port - b->port);
  }

  return return_value;
}

static void sort_hosts(memcached_st *ptr)
{
  if (memcached_server_count(ptr))
  {
    memcached_server_write_instance_st instance;

    qsort(memcached_server_list(ptr), memcached_server_count(ptr), sizeof(memcached_server_st), compare_servers);
    instance= memcached_server_instance_fetch(ptr, 0);
    instance->number_of_hosts= memcached_server_count(ptr);
  }
}


memcached_return_t run_distribution(memcached_st *ptr)
{
  if (ptr->flags.use_sort_hosts)
  {
    sort_hosts(ptr);
  }

  switch (ptr->distribution)
  {
  case MEMCACHED_DISTRIBUTION_CONSISTENT:
  case MEMCACHED_DISTRIBUTION_CONSISTENT_KETAMA:
  case MEMCACHED_DISTRIBUTION_CONSISTENT_KETAMA_SPY:
  case MEMCACHED_DISTRIBUTION_CONSISTENT_WEIGHTED:
    return update_continuum(ptr);

  case MEMCACHED_DISTRIBUTION_VIRTUAL_BUCKET:
  case MEMCACHED_DISTRIBUTION_MODULA:
    break;

  case MEMCACHED_DISTRIBUTION_RANDOM:
    srandom((uint32_t) time(NULL));
    break;

  case MEMCACHED_DISTRIBUTION_CONSISTENT_MAX:
  default:
    assert_msg(0, "Invalid distribution type passed to run_distribution()");
  }

  return MEMCACHED_SUCCESS;
}

static uint32_t ketama_server_hash(const char *key, size_t key_length, uint32_t alignment)
{
  unsigned char results[16];

  libhashkit_md5_signature((unsigned char*)key, key_length, results);

  return ((uint32_t) (results[3 + alignment * 4] & 0xFF) << 24)
    | ((uint32_t) (results[2 + alignment * 4] & 0xFF) << 16)
    | ((uint32_t) (results[1 + alignment * 4] & 0xFF) << 8)
    | (results[0 + alignment * 4] & 0xFF);
}

static int continuum_item_cmp(const void *t1, const void *t2)
{
  memcached_continuum_item_st *ct1= (memcached_continuum_item_st *)t1;
  memcached_continuum_item_st *ct2= (memcached_continuum_item_st *)t2;

  /* Why 153? Hmmm... */
  WATCHPOINT_ASSERT(ct1->value != 153);
  if (ct1->value == ct2->value)
    return 0;
  else if (ct1->value > ct2->value)
    return 1;
  else
    return -1;
}

static memcached_return_t update_continuum(memcached_st *ptr)
{
  uint32_t continuum_index= 0;
  memcached_server_st *list;
  uint32_t pointer_counter= 0;
  uint32_t pointer_per_server= MEMCACHED_POINTS_PER_SERVER;
  uint32_t pointer_per_hash= 1;
  uint32_t live_servers= 0;
  struct timeval now;

  if (gettimeofday(&now, NULL))
  {
    return memcached_set_errno(*ptr, errno, MEMCACHED_AT);
  }

  list= memcached_server_list(ptr);

  /* count live servers (those without a retry delay set) */
  bool is_auto_ejecting= _is_auto_eject_host(ptr);
  if (is_auto_ejecting)
  {
    live_servers= 0;
    ptr->ketama.next_distribution_rebuild= 0;
    for (uint32_t host_index= 0; host_index < memcached_server_count(ptr); ++host_index)
    {
      if (list[host_index].next_retry <= now.tv_sec)
      {
        live_servers++;
      }
      else
      {
        if (ptr->ketama.next_distribution_rebuild == 0 or list[host_index].next_retry < ptr->ketama.next_distribution_rebuild)
        {
          ptr->ketama.next_distribution_rebuild= list[host_index].next_retry;
        }
      }
    }
  }
  else
  {
    live_servers= memcached_server_count(ptr);
  }

  uint64_t is_ketama_weighted= memcached_behavior_get(ptr, MEMCACHED_BEHAVIOR_KETAMA_WEIGHTED);
  uint32_t points_per_server= (uint32_t) (is_ketama_weighted ? MEMCACHED_POINTS_PER_SERVER_KETAMA : MEMCACHED_POINTS_PER_SERVER);

  if (not live_servers)
  {
    return MEMCACHED_SUCCESS;
  }

  if (live_servers > ptr->ketama.continuum_count)
  {
    memcached_continuum_item_st *new_ptr;

    new_ptr= libmemcached_xrealloc(ptr, ptr->ketama.continuum, (live_servers + MEMCACHED_CONTINUUM_ADDITION) * points_per_server, memcached_continuum_item_st);

    if (new_ptr == 0)
    {
      return MEMCACHED_MEMORY_ALLOCATION_FAILURE;
    }

    ptr->ketama.continuum= new_ptr;
    ptr->ketama.continuum_count= live_servers + MEMCACHED_CONTINUUM_ADDITION;
  }

  uint64_t total_weight= 0;
  if (is_ketama_weighted)
  {
    for (uint32_t host_index = 0; host_index < memcached_server_count(ptr); ++host_index)
    {
      if (is_auto_ejecting == false or list[host_index].next_retry <= now.tv_sec)
      {
        total_weight += list[host_index].weight;
      }
    }
  }

  for (uint32_t host_index= 0; host_index < memcached_server_count(ptr); ++host_index)
  {
    if (is_auto_ejecting and list[host_index].next_retry > now.tv_sec)
    {
      continue;
    }

    if (is_ketama_weighted)
    {
        float pct= (float)list[host_index].weight / (float)total_weight;
        pointer_per_server= (uint32_t) ((::floor((float) (pct * MEMCACHED_POINTS_PER_SERVER_KETAMA / 4 * (float)live_servers + 0.0000000001))) * 4);
        pointer_per_hash= 4;
        if (DEBUG)
        {
          printf("ketama_weighted:%s|%d|%llu|%u\n",
                 list[host_index].hostname,
                 list[host_index].port,
                 (unsigned long long)list[host_index].weight,
                 pointer_per_server);
        }
    }


    if (ptr->distribution == MEMCACHED_DISTRIBUTION_CONSISTENT_KETAMA_SPY)
    {
      for (uint32_t pointer_index= 0;
           pointer_index < pointer_per_server / pointer_per_hash;
           pointer_index++)
      {
        char sort_host[1 +MEMCACHED_NI_MAXHOST +1 +MEMCACHED_NI_MAXSERV +1 + MEMCACHED_NI_MAXSERV ]= "";
        int sort_host_length;

        // Spymemcached ketema key format is: hostname/ip:port-index
        // If hostname is not available then: /ip:port-index
        sort_host_length= snprintf(sort_host, sizeof(sort_host),
                                   "/%s:%u-%u",
                                   list[host_index].hostname,
                                   (uint32_t)list[host_index].port,
                                   pointer_index);

        if (size_t(sort_host_length) >= sizeof(sort_host) or sort_host_length < 0)
        {
          return memcached_set_error(*ptr, MEMCACHED_MEMORY_ALLOCATION_FAILURE, MEMCACHED_AT, 
                                     memcached_literal_param("snprintf(sizeof(sort_host))"));
        }

        if (DEBUG)
        {
          fprintf(stdout, "update_continuum: key is %s\n", sort_host);
        }

        if (is_ketama_weighted)
        {
          for (uint32_t x= 0; x < pointer_per_hash; x++)
          {
            uint32_t value= ketama_server_hash(sort_host, (size_t)sort_host_length, x);
            ptr->ketama.continuum[continuum_index].index= host_index;
            ptr->ketama.continuum[continuum_index++].value= value;
          }
        }
        else
        {
          uint32_t value= hashkit_digest(&ptr->hashkit, sort_host, (size_t)sort_host_length);
          ptr->ketama.continuum[continuum_index].index= host_index;
          ptr->ketama.continuum[continuum_index++].value= value;
        }
      }
    }
    else
    {
      for (uint32_t pointer_index= 1;
           pointer_index <= pointer_per_server / pointer_per_hash;
           pointer_index++)
      {
        char sort_host[MEMCACHED_NI_MAXHOST +1 +MEMCACHED_NI_MAXSERV +1 +MEMCACHED_NI_MAXSERV]= "";
        int sort_host_length;

        if (list[host_index].port == MEMCACHED_DEFAULT_PORT)
        {
          sort_host_length= snprintf(sort_host, sizeof(sort_host),
                                     "%s-%u",
                                     list[host_index].hostname,
                                     pointer_index - 1);
        }
        else
        {
          sort_host_length= snprintf(sort_host, sizeof(sort_host),
                                     "%s:%u-%u",
                                     list[host_index].hostname,
                                     (uint32_t)list[host_index].port,
                                     pointer_index - 1);
        }

        if (size_t(sort_host_length) >= sizeof(sort_host) or sort_host_length < 0)
        {
          return memcached_set_error(*ptr, MEMCACHED_MEMORY_ALLOCATION_FAILURE, MEMCACHED_AT, 
                                     memcached_literal_param("snprintf(sizeof(sort_host)))"));
        }

        if (is_ketama_weighted)
        {
          for (uint32_t x = 0; x < pointer_per_hash; x++)
          {
            uint32_t value= ketama_server_hash(sort_host, (size_t)sort_host_length, x);
            ptr->ketama.continuum[continuum_index].index= host_index;
            ptr->ketama.continuum[continuum_index++].value= value;
          }
        }
        else
        {
          uint32_t value= hashkit_digest(&ptr->hashkit, sort_host, (size_t)sort_host_length);
          ptr->ketama.continuum[continuum_index].index= host_index;
          ptr->ketama.continuum[continuum_index++].value= value;
        }
      }
    }

    pointer_counter+= pointer_per_server;
  }

  WATCHPOINT_ASSERT(ptr);
  WATCHPOINT_ASSERT(ptr->ketama.continuum);
  WATCHPOINT_ASSERT(memcached_server_count(ptr) * MEMCACHED_POINTS_PER_SERVER <= MEMCACHED_CONTINUUM_SIZE);
  ptr->ketama.continuum_points_counter= pointer_counter;
  qsort(ptr->ketama.continuum, ptr->ketama.continuum_points_counter, sizeof(memcached_continuum_item_st), continuum_item_cmp);

  if (DEBUG)
  {
    for (uint32_t pointer_index= 0; memcached_server_count(ptr) && pointer_index < ((live_servers * MEMCACHED_POINTS_PER_SERVER) - 1); pointer_index++)
    {
      WATCHPOINT_ASSERT(ptr->ketama.continuum[pointer_index].value <= ptr->ketama.continuum[pointer_index + 1].value);
    }
  }

  return MEMCACHED_SUCCESS;
}

static memcached_return_t server_add(memcached_st *ptr, 
                                     const memcached_string_t& hostname,
                                     in_port_t port,
                                     uint32_t weight,
                                     memcached_connection_t type)
{
  assert_msg(ptr, "Programmer mistake, somehow server_add() was passed a NULL memcached_st");

  // if in STATIC mode do exactly what was there before
  if (memcached_is_static_client_mode(ptr))
  {
    memcached_server_st *new_host_list= libmemcached_xrealloc(ptr, memcached_server_list(ptr), (ptr->number_of_hosts + 1), memcached_server_st);
    
    if (new_host_list == NULL)
    {
      return memcached_set_error(*ptr, MEMCACHED_MEMORY_ALLOCATION_FAILURE, MEMCACHED_AT);
    }
    
    memcached_server_list_set(ptr, new_host_list);
    
    /* TODO: Check return type */
    memcached_server_write_instance_st instance= memcached_server_instance_fetch(ptr, memcached_server_count(ptr));
    
    if (__server_create_with(ptr, instance, hostname, port, weight, type) == NULL)
    {
      return memcached_set_error(*ptr, MEMCACHED_MEMORY_ALLOCATION_FAILURE, MEMCACHED_AT);
    }

    if (weight > 1)
    {
      ptr->ketama.weighted= true;      
    }
    
    ptr->number_of_hosts++;

    // @note we place the count in the bottom of the server list
    instance= memcached_server_instance_fetch(ptr, 0);
    memcached_servers_set_count(instance, memcached_server_count(ptr));
    return run_distribution(ptr);
  }

  // DYNAMIC OR UNDEFINED MODE

  if (memcached_config_server_fetch(ptr) != NULL)
  {
    // Already configured, so returning error
    return memcached_set_error(*ptr, MEMCACHED_CLIENT_ERROR, MEMCACHED_AT,
                               memcached_literal_param("DYNAMIC_MODE has already been initialized, cannot be initialized again."));
  }

  // currently in DYNAMIC mode with no initialization, or in UNDEFINED mode
  memcached_server_st *current_host_list = NULL;
  memcached_return_t error = MEMCACHED_SUCCESS;
  const char *host = memcached_c_str(hostname);
  current_host_list = memcached_server_list_append_with_weight(current_host_list, host, "", port, weight, &error);

  // if in dynamic mode then make sure to consider this host being the config endpoint
  memcached_server_st *list = NULL;
  list = get_server_list_if_dynamic_mode(ptr, current_host_list, &error);
  if (list != NULL and error == MEMCACHED_SUCCESS)
  {
    error = add_servers_to_client(ptr, list);
    if(memcached_is_dynamic_client_mode(ptr))
    {
      memcached_server_list_free(list);
    }
  }

  // the list created in this function is copied when used, so needs to be freed
  libmemcached_free(NULL, current_host_list);

  return error;
}

/**
 * Initialize the server with the configuration endpoint.
 */
memcached_return_t memcached_configserver_push(memcached_st *ptr, const memcached_server_st *configserver)
{
  if (configserver == NULL)
  {
    return MEMCACHED_NO_CONFIG_SERVER;
  }

  memcached_server_st *config_host;
  uint32_t count = 1;
  config_host= libmemcached_xrealloc(ptr, ptr->configserver, count, memcached_server_st);

  if (config_host == NULL)
  {
    return MEMCACHED_MEMORY_ALLOCATION_FAILURE;
  }

  memcached_configserver_set(ptr, config_host);

  memcached_server_write_instance_st instance;
  WATCHPOINT_ASSERT(configserver->hostname[0] != 0);

  // Config server is set in the client object. Find and use it.
  instance= memcached_config_server_fetch(ptr);
  WATCHPOINT_ASSERT(instance);

  memcached_string_t hostname= { memcached_string_make_from_cstr(configserver->hostname) };

  if(__server_create_with(ptr, instance,
                               hostname,
                               configserver->port, configserver->weight, configserver->type) == NULL)
  {
    return memcached_set_error(*ptr, MEMCACHED_MEMORY_ALLOCATION_FAILURE, MEMCACHED_AT);
  }

  ptr->configserver->options.is_allocated = true;

  return MEMCACHED_SUCCESS;
}


memcached_return_t add_servers_to_client(memcached_st *ptr, const memcached_server_list_st list)
{
  if (list == NULL)
  {
    return MEMCACHED_SUCCESS;
  }

  uint32_t count= memcached_server_list_count(list);

  memcached_server_st *new_host_list;
  new_host_list= libmemcached_xrealloc(ptr, memcached_server_list(ptr), (count + memcached_server_count(ptr)), memcached_server_st);

  if (new_host_list == NULL)
  {
    return MEMCACHED_MEMORY_ALLOCATION_FAILURE;
  }

  memcached_server_list_set(ptr, new_host_list);

  for (uint32_t x= 0; x < count; x++)
  {
    memcached_server_write_instance_st instance;

    WATCHPOINT_ASSERT(list[x].hostname[0] != 0);

    // We have extended the array, and now we will find it, and use it.
    instance= memcached_server_instance_fetch(ptr, memcached_server_count(ptr));
    WATCHPOINT_ASSERT(instance);

    memcached_string_t hostname= { memcached_string_make_from_cstr(list[x].hostname) };
    memcached_string_t ipaddress = { memcached_string_make_from_cstr(list[x].ipaddress) };

    if (__server_create_with(ptr, instance, 
                             hostname, ipaddress,
                             list[x].port, list[x].weight, list[x].type) == NULL)
    {
      return memcached_set_error(*ptr, MEMCACHED_MEMORY_ALLOCATION_FAILURE, MEMCACHED_AT);
    }

    if (list[x].weight > 1)
    {
      ptr->ketama.weighted= true;
    }

    ptr->number_of_hosts++;
  }

  // Provides backwards compatibility with server list.
  {
    memcached_server_write_instance_st instance;
    instance= memcached_server_instance_fetch(ptr, 0);
    instance->number_of_hosts= memcached_server_count(ptr);
  }

  return run_distribution(ptr);
}

memcached_return_t update_with_new_server_list(memcached_st *ptr, memcached_server_list_st new_server_list){
  if (new_server_list == NULL)
  {
    return MEMCACHED_SUCCESS;
  }

  uint32_t new_server_count = memcached_server_list_count(new_server_list);
  memcached_server_st *new_server_list_for_client = NULL;
  new_server_list_for_client = libmemcached_xrealloc(ptr, new_server_list_for_client, new_server_count, memcached_server_st);

  for (uint32_t x= 0; x < new_server_count; x++)
  {
    WATCHPOINT_ASSERT(new_server_list[x].hostname[0] != 0);

    memcached_server_write_instance_st instance= &new_server_list_for_client[x];

    memcached_string_t hostname = { memcached_string_make_from_cstr(new_server_list[x].hostname) };
    memcached_string_t ipaddress = { memcached_string_make_from_cstr(new_server_list[x].ipaddress) };
    if (__server_create_with(ptr, instance,
                             hostname, ipaddress,
                             new_server_list[x].port, new_server_list[x].weight, new_server_list[x].type) == NULL)
    {
      return memcached_set_error(*ptr, MEMCACHED_MEMORY_ALLOCATION_FAILURE, MEMCACHED_AT);
    }
  }

  memcached_server_st *old_server_list = memcached_server_list(ptr);

  memcached_server_list_set(ptr, new_server_list_for_client);
  ptr->number_of_hosts = new_server_count;

  // Provides backwards compatibility with server list.
  {
    memcached_server_write_instance_st instance;
    instance= memcached_server_instance_fetch(ptr, 0);
    if(instance != NULL){
      instance->number_of_hosts= memcached_server_count(ptr);
    }
  }
  memcached_return_t return_code = run_distribution(ptr);
  memcached_server_free(old_server_list);

  return return_code;
}

void reresolve_servers_in_client(memcached_server_list_st *server_list, uint32_t server_count){
  for(uint32_t x=0; x< server_count; x++){
    memcached_quit_server(server_list[x], false);
    memcached_connect_new_ipaddress(server_list[x]);
  }
}

/**
 * Updates the client object to add/remove/reresolve the server list. The sequence as specified in the input
 * server list is used while updating the client object.
 *
 * All servers are re-initialized using new list during add & remove scenario due to recreation of server array.
 * TODO: Refactor libmemcached code to use linked list. Lack of clean abstraction over server list
 * makes it a non-trivial task.
 */
memcached_return_t notify_server_list_update(memcached_st *ptr, memcached_server_list_st new_server_list)
{
  if (new_server_list == NULL)
  {
    return MEMCACHED_SUCCESS;
  }

  memcached_return_t return_code = MEMCACHED_SUCCESS;
  uint32_t new_servers_count = memcached_server_list_count(new_server_list);

  memcached_server_st *current_server_list = ptr->servers;
  uint32_t current_servers_count = memcached_server_count(ptr);

  memcached_server_list_st *servers_to_reresolve = NULL;
  servers_to_reresolve = libmemcached_xrealloc(NULL, servers_to_reresolve, current_servers_count, memcached_server_list_st);
  uint32_t reresolve_count = 0;

  //Start with full servers count and start counting down as servers are matched.
  uint32_t remove_servers_count = current_servers_count;

  bool are_there_new_servers = false;
  for(uint32_t x= 0; x< new_servers_count; x++)
  {
    bool host_matched = false;
    for(uint32_t y=0; y< current_servers_count; y++)
    {
      if(strcmp( new_server_list[x].hostname, current_server_list[y].hostname) == 0 && new_server_list[x].port == current_server_list[y].port)
      {
        host_matched = true;
        remove_servers_count--;
        bool has_ipaddress = has_memcached_server_ipaddress(&new_server_list[x]);
        if(has_ipaddress){
          bool has_existing_ipaddress = has_memcached_server_ipaddress(&current_server_list[y]);
          if(!has_existing_ipaddress || strcmp(new_server_list[x].ipaddress, current_server_list[y].ipaddress) != 0)
          {
            servers_to_reresolve[reresolve_count] = &current_server_list[y];
            memcached_string_t _ipaddress = { memcached_string_make_from_cstr(new_server_list[x].ipaddress) };
            memcached_update_ipaddress(&current_server_list[y], _ipaddress);
            reresolve_count++;
          }
        }
        break;
      }
    }
    if(!host_matched)
    {
      are_there_new_servers = true;
      break;
    }
  }

  if(are_there_new_servers || remove_servers_count > 0)
  {
    //The entire server list is updated as per the new list. Hence return immediately.
    return_code = update_with_new_server_list(ptr, new_server_list);
  }
  else if(reresolve_count > 0)
  {
    servers_to_reresolve = libmemcached_xrealloc(ptr, servers_to_reresolve, reresolve_count, memcached_server_list_st);
    reresolve_servers_in_client(servers_to_reresolve, reresolve_count);
  }

  libmemcached_free(NULL, servers_to_reresolve);

  return return_code;
}

/**
  * Parse response from getConfig for cluster type. The response format is as follows:
  *
  * version number
  * hostname1|ipaddress1|port hostname2|ipaddress2|port
  *
  * returns the ClusterConfiguration object which contains the parsed results.
  */
memcached_server_st *parse_memcached_configuration(char *config){
    char *string;
    const char *begin_ptr;
    const char *end_ptr;
    memcached_server_st *servers= NULL;
    memcached_return_t rc;

    if(config == NULL)
    {
      return NULL;
    }

    uint32_t config_length = strlen(config);
    //Safety check if config string is unreasonbly long.
    if(config_length > HUGE_STRING_LEN)
    {
      return NULL;
    }

    end_ptr= config + strlen(config);

    //Skip version number
    config = (char *)index(config, '\n');
    if(config == NULL)
    {
      return NULL;
    }

    config++;

    for (begin_ptr= config, string= (char *)index(config, ' ');
         begin_ptr != end_ptr;
         string= (char *)index(begin_ptr, ' '))
    {
      char buffer[HUGE_STRING_LEN];
      uint32_t weight= 0;

      if (isspace(*begin_ptr))
      {
        begin_ptr++;
        continue;
      }

      if (string)
      {
        memcpy(buffer, begin_ptr, (size_t) (string - begin_ptr));
        buffer[(unsigned int)(string - begin_ptr)]= 0;
        begin_ptr= string+1;
      }
      else
      {
        size_t length= strlen(begin_ptr);
        memcpy(buffer, begin_ptr, length);
        buffer[length]= 0;
        begin_ptr= end_ptr;
      }

      char *ptr_for_ip_field = index(buffer, '|');
      if(ptr_for_ip_field == NULL)
      {
        return NULL;
     }

      //End buffer field for hostname
      ptr_for_ip_field[0] = 0;

      ptr_for_ip_field++;

      char *ptr_for_port_field = index(ptr_for_ip_field, '|');
      if(ptr_for_port_field == NULL)
      {
        return NULL;
      }

      char ipaddress_buffer[IP_ADDRESS_LENGTH];

      if(*ptr_for_ip_field != '|')
      {
        size_t length = (size_t) (ptr_for_port_field - ptr_for_ip_field);
        if(length >= IP_ADDRESS_LENGTH)
        {
          return NULL;
        }
        memcpy(ipaddress_buffer, ptr_for_ip_field, length);
      }
      ipaddress_buffer[(unsigned int)(ptr_for_port_field - ptr_for_ip_field)] = 0;

      in_port_t port= 0;
      ptr_for_port_field++;

      port= (in_port_t) strtoul(ptr_for_port_field, (char **)NULL, 10);
      servers= memcached_server_list_append_with_weight(servers, buffer, ipaddress_buffer, port, weight, &rc);

    }

  return servers;
}

/**
 * For customer convenience, the existing API is used as is to initialize the 
 * memcached client with configuration endpoint. The set of memcached nodes 
 * are retrieved from the configuration endpoint.
 */
memcached_return_t memcached_server_push(memcached_st *ptr, const memcached_server_list_st list)
{
  memcached_return_t error = MEMCACHED_SUCCESS;
  memcached_server_st *servers = get_server_list_if_dynamic_mode(ptr, list, &error);
  if (servers != NULL and error == MEMCACHED_SUCCESS)
  {
    error = add_servers_to_client(ptr, servers);
    if(memcached_is_dynamic_client_mode(ptr))
    {
      memcached_server_list_free(servers);
    }
  }

  return error;
}

char inline *_retrieve_config_with_retries(memcached_st *ptr, memcached_return_t *error)
{
  size_t value_length;
  uint32_t flags;
  char *config = NULL;
  int retry_count = 0;
  while(retry_count < 3)
  {
    // update the last attempted time with each try, prevents first operation
    // from retrieving config
    ptr->polling.last_attempted = time(NULL);

    config = memcached_config_get(ptr->configserver, ptr, &value_length, &flags, error);
    if (*error == MEMCACHED_SUCCESS)
    {
      break;
    }
    else
    {
      retry_count++;
      if (config != NULL) free(config);
    }
  }

  return config;
}

/**
 * Tests if the list provided contains only one server, and if that server has
 * a subdomain of '.cfg.'. If both conditions are met, returns true, otherwise
 * returns false.
 */
static inline bool should_init_dynamic_mode(const memcached_server_list_st list)
{
  if (memcached_server_list_count(list) == 1 && 
      strstr(memcached_server_name(&list[0]), ".cfg.") != NULL)
  {
    return true;
  }
  else
  {
    return false;
  }
}

/**
 * This method is responsible for initializing the client to use the list of 
 * servers retrieved from the config endpoint if in Dynamic mode, or else
 * use the list of servers provided.
 *
 * Returns the list to add.
 *
 * If UNDEFINED (not client mode specified) then see if the list
 * provided only has one entry, and if that entry's hostname contains '.cfg.'.
 * If so, then consider the client to be in DYNAMIC mode and consider the
 * provided entry as the configuration endpoint. Use this endpoint to 
 * retrieve and initialize the client. If not, consider the client to be in
 * STATIC mode and initialize accordingly.
 *
 * If unable to retrieve the configuration (when in dynamic mode) then consider
 * a 'soft' failure and return NULL. The callers should still consider this
 * a successful initialization. This is to mimic the behavior of server_add in 
 * static mode - if the server is not actually available for connection
 * the server_add call does not fail. It will fail on the first operation 
 * attempted to that server.
 */
memcached_server_st *get_server_list_if_dynamic_mode(memcached_st *ptr, const memcached_server_list_st list, memcached_return_t *error)
{
  assert_msg(ptr, "Programmer error, get_server_list_if_dynamic_mode called NULL ptr pointer");
  assert_msg(error, "Programmer error, get_server_list_if_dynamic_mode called NULL error pointer");

  if (memcached_is_static_client_mode(ptr))
  {
    return list;
  }
  else if (memcached_is_dynamic_client_mode(ptr) or should_init_dynamic_mode(list))
  {
    // DYNAMIC OR UNDEFINED client mode with one server that has '.cfg.' subdomain in it.

    // DYNAMIC mode and UDP are not supported.
    if (memcached_is_udp(ptr))
    {
      *error = memcached_set_error(*ptr, MEMCACHED_NOT_SUPPORTED, MEMCACHED_AT,
                                   memcached_literal_param("UDP is not supported with CLIENT_MODE set to DYNAMIC_MODE."));
      return NULL;
    }

    // Already initialized in DYNAMIC mode, cannot be initialized again.
    if (memcached_config_server_fetch(ptr) != NULL)
    {
      *error = memcached_set_error(*ptr, MEMCACHED_CLIENT_ERROR, MEMCACHED_AT,
                                   memcached_literal_param("DYNAMIC_MODE has already been initialized, cannot be initialized again."));
      return NULL;
    }

    // DYNAMIC MODE
    memcached_configserver_push(ptr, list);
    memcached_behavior_set(ptr, MEMCACHED_BEHAVIOR_CLIENT_MODE, DYNAMIC_MODE);

    char *config = _retrieve_config_with_retries(ptr, error);
    if (config != NULL and *error == MEMCACHED_SUCCESS)
    {
      // since received config, store it so not retrieved again on first operation
      memcached_return_t rc = complete_dynamic_initialization(ptr, config);
      if (rc != MEMCACHED_SUCCESS)
      {
        // intentionally not setting *error = rc, since PARSE_ERROR should be a 
        // transient/soft failure.
        libmemcached_free(ptr, config);
        return NULL;
      }

      // Parse the config data to build memcached server objects
      memcached_server_st *servers = parse_memcached_configuration(config);
      libmemcached_free(ptr, config);
      return servers;
    }
    else 
    {
      // cannot initialize client, return NULL since this could be a 
      // transient failure.
      *error = MEMCACHED_SUCCESS;
      libmemcached_free(ptr, config);
      return NULL;
    }
  }
  else
  {
    // UNDEFINED mode being treated as STATIC mode
    memcached_behavior_set(ptr, MEMCACHED_BEHAVIOR_CLIENT_MODE, STATIC_MODE);
    return list;
  }    
}

memcached_return_t memcached_server_add_unix_socket(memcached_st *ptr,
                                                    const char *filename)
{
  return memcached_server_add_unix_socket_with_weight(ptr, filename, 0);
}

memcached_return_t memcached_server_add_unix_socket_with_weight(memcached_st *ptr,
                                                                const char *filename,
                                                                uint32_t weight)
{
  if (ptr == NULL)
  {
    return MEMCACHED_FAILURE;
  }

  memcached_string_t _filename= { memcached_string_make_from_cstr(filename) };
  if (memcached_is_valid_servername(_filename) == false)
  {
    memcached_set_error(*ptr, MEMCACHED_INVALID_ARGUMENTS, MEMCACHED_AT, memcached_literal_param("Invalid filename for socket provided"));
  }

  return server_add(ptr, _filename, 0, weight, MEMCACHED_CONNECTION_UNIX_SOCKET);
}

memcached_return_t memcached_server_add_udp(memcached_st *ptr,
                                            const char *hostname,
                                            in_port_t port)
{
  return memcached_server_add_udp_with_weight(ptr, hostname, port, 0);
}

memcached_return_t memcached_server_add_udp_with_weight(memcached_st *ptr,
                                                        const char *,
                                                        in_port_t,
                                                        uint32_t)
{
  if (ptr == NULL)
  {
    return MEMCACHED_INVALID_ARGUMENTS;
  }

  return memcached_set_error(*ptr, MEMCACHED_DEPRECATED, MEMCACHED_AT);
}

memcached_return_t memcached_server_add(memcached_st *ptr,
                                        const char *hostname,
                                        in_port_t port)
{
  return memcached_server_add_with_weight(ptr, hostname, port, 0);
}

memcached_return_t memcached_server_add_with_weight(memcached_st *ptr,
                                                    const char *hostname,
                                                    in_port_t port,
                                                    uint32_t weight)
{
  if (ptr == NULL)
  {
    return MEMCACHED_INVALID_ARGUMENTS;
  }

  if (port == 0)
  {
    port= MEMCACHED_DEFAULT_PORT;
  }

  size_t hostname_length= hostname ? strlen(hostname) : 0;
  if (hostname_length == 0)
  {
    hostname= "localhost";
    hostname_length= memcached_literal_param_size("localhost");
  }

  memcached_string_t _hostname= { hostname, hostname_length };

  if (memcached_is_valid_servername(_hostname) == false)
  {
    return memcached_set_error(*ptr, MEMCACHED_INVALID_ARGUMENTS, MEMCACHED_AT, memcached_literal_param("Invalid hostname provided"));
  }

  return server_add(ptr, _hostname, port, weight, _hostname.c_str[0] == '/' ? MEMCACHED_CONNECTION_UNIX_SOCKET  : MEMCACHED_CONNECTION_TCP);
}

memcached_return_t memcached_server_add_parsed(memcached_st *ptr,
                                               const char *hostname,
                                               size_t hostname_length,
                                               in_port_t port,
                                               uint32_t weight)
{
  char buffer[NI_MAXHOST];

  memcpy(buffer, hostname, hostname_length);
  buffer[hostname_length]= 0;

  memcached_string_t _hostname= { buffer, hostname_length };

  return server_add(ptr, _hostname,
                    port,
                    weight,
                    MEMCACHED_CONNECTION_TCP);
}
