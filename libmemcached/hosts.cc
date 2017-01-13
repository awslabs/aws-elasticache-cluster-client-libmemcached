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

#include <libmemcached/common.h>
#include "libmemcached/assert.hpp"

#include <cmath>
#include <sys/time.h>

/* Protoypes (static) */
static memcached_return_t update_continuum(Memcached *ptr);

static int compare_servers(const void *p1, const void *p2)
{
  const memcached_instance_st * a= (const memcached_instance_st *)p1;
  const memcached_instance_st * b= (const memcached_instance_st *)p2;

  int return_value= strcmp(a->_hostname, b->_hostname);

  if (return_value == 0)
  {
    return_value= int(a->port() - b->port());
  }

  return return_value;
}

static void sort_hosts(Memcached *ptr)
{
  if (memcached_server_count(ptr))
  {
    qsort(memcached_instance_list(ptr), memcached_server_count(ptr), sizeof(memcached_instance_st), compare_servers);
  }
}


memcached_return_t run_distribution(Memcached *ptr)
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
  {
    return 0;
  }
  else if (ct1->value > ct2->value)
  {
    return 1;
  }
  else
  {
    return -1;
}
}

static memcached_return_t update_continuum(Memcached *ptr)
{
  uint32_t continuum_index= 0;
  uint32_t pointer_counter= 0;
  uint32_t pointer_per_server= MEMCACHED_POINTS_PER_SERVER;
  uint32_t pointer_per_hash= 1;
  uint32_t live_servers= 0;
  struct timeval now;

  if (gettimeofday(&now, NULL))
  {
    return memcached_set_errno(*ptr, errno, MEMCACHED_AT);
  }

  memcached_instance_st* list= memcached_instance_list(ptr);

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

  uint32_t points_per_server= (uint32_t) (memcached_is_weighted_ketama(ptr) ? MEMCACHED_POINTS_PER_SERVER_KETAMA : MEMCACHED_POINTS_PER_SERVER);

  if (live_servers == 0)
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
  assert_msg(ptr->ketama.continuum, "Programmer Error, empty ketama continuum");

  uint64_t total_weight= 0;
  if (memcached_is_weighted_ketama(ptr))
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

    if (memcached_is_weighted_ketama(ptr))
    {
        float pct= (float)list[host_index].weight / (float)total_weight;
        pointer_per_server= (uint32_t) ((::floor((float) (pct * MEMCACHED_POINTS_PER_SERVER_KETAMA / 4 * (float)live_servers + 0.0000000001))) * 4);
        pointer_per_hash= 4;
        if (DEBUG)
        {
          printf("ketama_weighted:%s|%d|%llu|%u\n",
                 list[host_index]._hostname,
                 list[host_index].port(),
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
                                   list[host_index]._hostname,
                                   (uint32_t)list[host_index].port(),
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

        if (memcached_is_weighted_ketama(ptr))
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

        if (list[host_index].port() == MEMCACHED_DEFAULT_PORT)
        {
          sort_host_length= snprintf(sort_host, sizeof(sort_host),
                                     "%s-%u",
                                     list[host_index]._hostname,
                                     pointer_index - 1);
        }
        else
        {
          sort_host_length= snprintf(sort_host, sizeof(sort_host),
                                     "%s:%u-%u",
                                     list[host_index]._hostname,
                                     (uint32_t)list[host_index].port(),
                                     pointer_index - 1);
        }

        if (size_t(sort_host_length) >= sizeof(sort_host) or sort_host_length < 0)
        {
          return memcached_set_error(*ptr, MEMCACHED_MEMORY_ALLOCATION_FAILURE, MEMCACHED_AT, 
                                     memcached_literal_param("snprintf(sizeof(sort_host)))"));
        }

        if (memcached_is_weighted_ketama(ptr))
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

  assert_msg(ptr, "Programmer Error, no valid ptr");
  assert_msg(ptr->ketama.continuum, "Programmer Error, empty ketama continuum");
  assert_msg(memcached_server_count(ptr) * MEMCACHED_POINTS_PER_SERVER <= MEMCACHED_CONTINUUM_SIZE, "invalid size information being given to qsort()");
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

static memcached_return_t server_add(Memcached *memc, 
                                     const memcached_string_t& hostname,
                                     in_port_t port,
                                     uint32_t weight,
                                     memcached_connection_t type)
{
  assert_msg(memc, "Programmer mistake, somehow server_add() was passed a NULL memcached_st");

  if (memc->number_of_hosts)
  {
    assert(memcached_instance_list(memc));
  }

  if (memcached_instance_list(memc))
  {
    assert(memc->number_of_hosts);
  }
  
  // if in STATIC mode do exactly what was there before
  if (memcached_is_static_client_mode(memc))
  {
    uint32_t host_list_size= memc->number_of_hosts +1;
    memcached_instance_st* new_host_list= libmemcached_xrealloc(memc, memcached_instance_list(memc), host_list_size, memcached_instance_st);

    if (new_host_list == NULL)
    {
      return memcached_set_error(*memc, MEMCACHED_MEMORY_ALLOCATION_FAILURE, MEMCACHED_AT);
    }

    memcached_instance_set(memc, new_host_list, host_list_size);
    assert(memc->number_of_hosts == host_list_size);

    /* TODO: Check return type */
    memcached_instance_st* instance= memcached_instance_fetch(memc, memcached_server_count(memc) -1);

    if (__instance_create_with(memc, instance, hostname, port, weight, type) == NULL)
    {
      return memcached_set_error(*memc, MEMCACHED_MEMORY_ALLOCATION_FAILURE, MEMCACHED_AT);
    }

    if (weight > 1)
    {
      if (memcached_is_consistent_distribution(memc))
      {
        memcached_set_weighted_ketama(memc, true);
      }
    }

    return run_distribution(memc);
  }

  // DYNAMIC OR UNDEFINED MODE

  if (memcached_config_server_fetch(memc) != NULL)
  {
    // Already configured, so returning error
    return memcached_set_error(*memc, MEMCACHED_CLIENT_ERROR, MEMCACHED_AT,
                               memcached_literal_param("DYNAMIC_MODE has already been initialized, cannot be initialized again."));
  }

  // currently in DYNAMIC mode with no initialization, or in UNDEFINED mode
  memcached_server_st *current_host_list = NULL;
  memcached_return_t error = MEMCACHED_SUCCESS;
  const char *host = memcached_c_str(hostname);
  current_host_list = memcached_server_list_append_with_weight(current_host_list, host, "", port, weight, &error);

  // if in dynamic mode then make sure to consider this host being the config endpoint
  memcached_server_st *list = NULL;
  list = get_server_list_if_dynamic_mode(memc, current_host_list, &error);
  if (list != NULL)
  {
    assert(error == MEMCACHED_SUCCESS);
    error = add_servers_to_client(memc, list);
    if(list != current_host_list)
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

  memcached_instance_st *config_host;
  uint32_t count = 1;
  config_host= libmemcached_xrealloc(ptr, ptr->configserver, count, memcached_instance_st);

  if (config_host == NULL)
  {
    return MEMCACHED_MEMORY_ALLOCATION_FAILURE;
  }

  memcached_configserver_set(ptr, config_host);

  memcached_instance_st *instance;
  WATCHPOINT_ASSERT(configserver->hostname[0] != 0);

  // Config server is set in the client object. Find and use it.
  instance= memcached_config_server_fetch(ptr);
  WATCHPOINT_ASSERT(instance);

  memcached_string_t hostname= { memcached_string_make_from_cstr(configserver->hostname) };

  if(__instance_create_with(ptr, instance,
                               hostname,
                               configserver->port, configserver->weight, configserver->type) == NULL)
  {
    return memcached_set_error(*ptr, MEMCACHED_MEMORY_ALLOCATION_FAILURE, MEMCACHED_AT);
  }

  ptr->configserver->options.is_allocated = true;

  return MEMCACHED_SUCCESS;
}


memcached_return_t add_servers_to_client(memcached_st *shell, const memcached_server_list_st list)
{
  if (list == NULL)
  {
    return MEMCACHED_SUCCESS;
  }

  Memcached* ptr= memcached2Memcached(shell);
  if (ptr)
  {
    uint32_t original_host_size= memcached_server_count(ptr);
    uint32_t count= memcached_server_list_count(list);
    uint32_t host_list_size= count +original_host_size;

    memcached_instance_st* new_host_list= libmemcached_xrealloc(ptr, memcached_instance_list(ptr), host_list_size, memcached_instance_st);

    if (new_host_list == NULL)
    {
      return MEMCACHED_MEMORY_ALLOCATION_FAILURE;
    }

    memcached_instance_set(ptr, new_host_list, host_list_size);

    ptr->state.is_parsing= true;
    for (uint32_t x= 0; x < count; ++x, ++original_host_size)
    {
      WATCHPOINT_ASSERT(list[x].hostname[0] != 0);

      // We have extended the array, and now we will find it, and use it.
      memcached_instance_st* instance= memcached_instance_fetch(ptr, original_host_size);
      WATCHPOINT_ASSERT(instance);

      memcached_string_t hostname= { memcached_string_make_from_cstr(list[x].hostname) };
      memcached_string_t ipaddress = { memcached_string_make_from_cstr(list[x].ipaddress) };
      if (__instance_create_with(ptr, instance, 
                             hostname, ipaddress,
                             list[x].port, list[x].weight, list[x].type) == NULL)
      {
        ptr->state.is_parsing= false;
        return memcached_set_error(*ptr, MEMCACHED_MEMORY_ALLOCATION_FAILURE, MEMCACHED_AT);
      }

      if (list[x].weight > 1)
      {
        memcached_set_weighted_ketama(ptr, true);
      }
    }
    ptr->state.is_parsing= false;

    return run_distribution(ptr);
  }

  return MEMCACHED_INVALID_ARGUMENTS;
}

memcached_return_t add_instances_to_client(memcached_st *ptr, const struct memcached_instance_st* list, uint32_t number_of_hosts)
{
  if (list == NULL)
  {
    return MEMCACHED_SUCCESS;
  }

  uint32_t original_host_size= memcached_server_count(ptr);
  uint32_t host_list_size= number_of_hosts +original_host_size;
  memcached_instance_st* new_host_list= libmemcached_xrealloc(ptr, memcached_instance_list(ptr), host_list_size, memcached_instance_st);

  if (new_host_list == NULL)
  {
    return MEMCACHED_MEMORY_ALLOCATION_FAILURE;
  }

  memcached_instance_set(ptr, new_host_list, host_list_size);

  // We don't bother with lookups for this operation
  ptr->state.is_parsing= true;

  // We use original_host_size since size will now point to the first new
  // instance allocated.
  for (uint32_t x= 0; x < number_of_hosts; ++x, ++original_host_size)
  {
    WATCHPOINT_ASSERT(list[x]._hostname[0] != 0);

    // We have extended the array, and now we will find it, and use it.
    memcached_instance_st* instance= memcached_instance_fetch(ptr, original_host_size);
    WATCHPOINT_ASSERT(instance);

    memcached_string_t hostname= { memcached_string_make_from_cstr(list[x]._hostname) };
    if (__instance_create_with(ptr, instance, 
                               hostname,
                               list[x].port(), list[x].weight, list[x].type) == NULL)
    {
      ptr->state.is_parsing= false;
      return memcached_set_error(*ptr, MEMCACHED_MEMORY_ALLOCATION_FAILURE, MEMCACHED_AT);
    }

    if (list[x].weight > 1)
    {
      memcached_set_weighted_ketama(ptr, true);
    }
  }
  ptr->state.is_parsing= false;

  return run_distribution(ptr);
}


/**
 * Creates a new array of `memcached_server_st` type identical to the source array of type `memcached_instance_st` type and
 * puts a pointer to it into the memory pointed by the `dst_list` argument (which MUST be null prior to calling the function).
 * If source list is null will return null and no errors.
 *
 * This method and it's counterpart below, _convert_server_list_to_instance_list(), are used to convert back and forth between the old server struct and the new instance
 * count and are used from memcached_instance_push() so that we can reuse the implementation of get_server_list_if_dynamic_mode() and the helper methods it calls, like
 * memcached_configserver_push() that all take on the old (`memcached_server_st`) data structure as input. An alternative of doing this conversion whould have been
 * to add new variants of those methods that would take `memcached_instance_st` argument. We chose not to do that to avoid code duplication and keep changes to as
 * minimal as possible. If the old structure is deprecated and removed in the upstream project in the future, these conversion methods may be used as reference
 * to guide re-implementation of get_server_list_if_dynamic_mode() and company using the new structure (class).
 */
memcached_return_t _convert_instance_list_to_server_list(memcached_st *ptr, const memcached_instance_st* src_list, uint32_t number_of_hosts, memcached_server_st **dst_list)
{
  assert(*dst_list == NULL);
  memcached_return_t error = MEMCACHED_SUCCESS;
  if (src_list != NULL)
  {
    for (uint32_t i = 0; i < number_of_hosts; i++)
    {
      // TODO: Doesn't take memcached_st* -> doesnt' allocate???
      *dst_list = memcached_server_list_append_with_weight(*dst_list,
                                                   src_list[i]._hostname, src_list[i]._ipaddress,
                                                   src_list[i].port_, src_list[i].weight, &error);
      if (memcached_failed(error))
      {
        if (*dst_list != NULL) {
           memcached_server_list_free(*dst_list);
           *dst_list = NULL;
        }
        break;
      }
    }
  }
  return error;
}

/**
 * Creates a new array of `memcached_instance_st` type identical to the source array of type `memcached_server_st` type and
 * puts a pointer to it into the memory pointed by the `dst_list` argument (which MUST be null prior to calling the function) and
 * its size into memory pointed by the `dst_number_of_hosts` argument. If source list is null will return null and no errors.
 */
memcached_return_t _convert_server_list_to_instance_list(memcached_st *ptr, memcached_server_st* src_list, uint32_t *dst_number_of_hosts, memcached_instance_st **dst_list)
{
  assert(*dst_list == NULL);
  *dst_number_of_hosts = 0;
  if (src_list != NULL)
  {
    uint32_t src_list_number = memcached_server_list_count(src_list);
    *dst_list = libmemcached_xvalloc(ptr, src_list_number, memcached_instance_st);
    if (*dst_list == NULL) {
        return MEMCACHED_MEMORY_ALLOCATION_FAILURE;
    }
    for (uint32_t i = 0; i < src_list_number; i++)
    {
    memcached_string_t hostname = { memcached_string_make_from_cstr(src_list[i].hostname) };
    memcached_string_t ipaddress = { memcached_string_make_from_cstr(src_list[i].ipaddress) };
      if (__instance_create_with(ptr, &(*dst_list)[i],
                          hostname, ipaddress,
                          src_list[i].port, src_list[i].weight, src_list[i].type) == NULL)
      {
        memcached_instance_list_free(*dst_list, i);
        *dst_list = NULL;
        return MEMCACHED_MEMORY_ALLOCATION_FAILURE;
      }
    }
    *dst_number_of_hosts = src_list_number;
  }
  return MEMCACHED_SUCCESS;
}

/**
 * Same as memcached_server_push() but using the new data structure. Also see comments for _convert_instance_list_to_server_list().
 */
memcached_return_t memcached_instance_push(memcached_st *ptr, const struct memcached_instance_st* list, uint32_t number_of_hosts)
{
  memcached_return_t error = MEMCACHED_SUCCESS;

  memcached_server_st *s_list = NULL;
  error = _convert_instance_list_to_server_list(ptr, list, number_of_hosts, &s_list);
  if (memcached_failed(error))
  {
    return error;
  }

  memcached_server_st *servers = get_server_list_if_dynamic_mode(ptr, s_list, &error);
  if (servers != NULL)
  {
    assert(error == MEMCACHED_SUCCESS);
    memcached_instance_st *i_servers = NULL;
    uint32_t servers_number_of_hosts;
    error = _convert_server_list_to_instance_list(ptr, servers, &servers_number_of_hosts, &i_servers);
    if (!memcached_failed(error))
    {
      error = add_instances_to_client(ptr, i_servers, servers_number_of_hosts);
      memcached_instance_list_free(i_servers, servers_number_of_hosts);
    }
    if(servers != s_list)
    {
      memcached_server_list_free(servers);
    }
  }

  memcached_server_list_free(s_list);
  return error;
}


memcached_return_t update_with_new_server_list(memcached_st *ptr, memcached_server_list_st new_server_list){
  if (new_server_list == NULL)
  {
    return MEMCACHED_SUCCESS;
  }

  uint32_t new_server_count = memcached_server_list_count(new_server_list);
  memcached_instance_st *new_server_list_for_client = NULL;
  new_server_list_for_client = libmemcached_xrealloc(ptr, new_server_list_for_client, new_server_count, memcached_instance_st);

  for (uint32_t x= 0; x < new_server_count; x++)
  {
    WATCHPOINT_ASSERT(new_server_list[x].hostname[0] != 0);

    memcached_instance_st *instance= &new_server_list_for_client[x];

    memcached_string_t hostname = { memcached_string_make_from_cstr(new_server_list[x].hostname) };
    memcached_string_t ipaddress = { memcached_string_make_from_cstr(new_server_list[x].ipaddress) };
    if (__instance_create_with(ptr, instance,
                             hostname, ipaddress,
                             new_server_list[x].port, new_server_list[x].weight, new_server_list[x].type) == NULL)
    {
      return memcached_set_error(*ptr, MEMCACHED_MEMORY_ALLOCATION_FAILURE, MEMCACHED_AT);
    }
  }

  memcached_instance_st *old_server_list = memcached_instance_list(ptr);
  uint32_t old_server_count = memcached_server_count(ptr);

  memcached_instance_set(ptr, new_server_list_for_client, new_server_count);

  memcached_return_t return_code = run_distribution(ptr);
  memcached_instance_list_free(old_server_list, old_server_count);

  return return_code;
}

void reresolve_servers_in_client(memcached_instance_st ** server_list, uint32_t server_count){
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

  memcached_instance_st *current_server_list = ptr->servers;
  uint32_t current_servers_count = memcached_server_count(ptr);

  memcached_instance_st **servers_to_reresolve = NULL;
  servers_to_reresolve = libmemcached_xrealloc(NULL, servers_to_reresolve, current_servers_count, memcached_instance_st*);
  uint32_t reresolve_count = 0;

  //Start with full servers count and start counting down as servers are matched.
  uint32_t remove_servers_count = current_servers_count;

  bool are_there_new_servers = false;
  for(uint32_t x= 0; x< new_servers_count; x++)
  {
    bool host_matched = false;
    for(uint32_t y=0; y< current_servers_count; y++)
    {
      if(strcmp( new_server_list[x].hostname, current_server_list[y]._hostname) == 0 && new_server_list[x].port == current_server_list[y].port_)
      {
        host_matched = true;
        remove_servers_count--;
        bool has_ipaddress = has_memcached_server_ipaddress(&new_server_list[x]);
        if(has_ipaddress){
          bool has_existing_ipaddress = has_memcached_instance_ipaddress(&current_server_list[y]);
          if(!has_existing_ipaddress || strcmp(new_server_list[x].ipaddress, current_server_list[y]._ipaddress) != 0)
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
    servers_to_reresolve = libmemcached_xrealloc(ptr, servers_to_reresolve, reresolve_count, memcached_instance_st*);
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
  if (servers != NULL)
  {
    assert(error == MEMCACHED_SUCCESS);
    error = add_servers_to_client(ptr, servers);
    if(servers != list)
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
static inline bool should_init_dynamic_mode(memcached_server_list_st list)
{
  if (memcached_server_list_count(list) == 1 && 
      strstr(list[0].hostname, ".cfg.") != NULL)
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

memcached_return_t memcached_server_add_unix_socket_with_weight(memcached_st *shell,
                                                                const char *filename,
                                                                uint32_t weight)
{
  Memcached* ptr= memcached2Memcached(shell);
  if (ptr)
  {
  memcached_string_t _filename= { memcached_string_make_from_cstr(filename) };
    if (memcached_is_valid_filename(_filename) == false)
  {
      return memcached_set_error(*ptr, MEMCACHED_INVALID_ARGUMENTS, MEMCACHED_AT, memcached_literal_param("Invalid filename for socket provided"));
  }

  return server_add(ptr, _filename, 0, weight, MEMCACHED_CONNECTION_UNIX_SOCKET);
}

  return MEMCACHED_FAILURE;
}

memcached_return_t memcached_server_add_udp(memcached_st *ptr,
                                            const char *hostname,
                                            in_port_t port)
{
  return memcached_server_add_udp_with_weight(ptr, hostname, port, 0);
}

memcached_return_t memcached_server_add_udp_with_weight(memcached_st *shell,
                                                        const char *,
                                                        in_port_t,
                                                        uint32_t)
{
  Memcached* self= memcached2Memcached(shell);
  if (self)
  {
    return memcached_set_error(*self, MEMCACHED_DEPRECATED, MEMCACHED_AT);
  }

  return MEMCACHED_INVALID_ARGUMENTS;
}

memcached_return_t memcached_server_add(memcached_st *shell,
                                        const char *hostname,
                                        in_port_t port)
{
  return memcached_server_add_with_weight(shell, hostname, port, 0);
}

memcached_return_t memcached_server_add_with_weight(memcached_st *shell,
                                                    const char *hostname,
                                                    in_port_t port,
                                                    uint32_t weight)
{
  Memcached* ptr= memcached2Memcached(shell);
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
  char buffer[MEMCACHED_NI_MAXHOST]= { 0 };

  memcpy(buffer, hostname, hostname_length);
  buffer[hostname_length]= 0;

  memcached_string_t _hostname= { buffer, hostname_length };

  return server_add(ptr, _hostname,
                    port,
                    weight,
                    MEMCACHED_CONNECTION_TCP);
}
