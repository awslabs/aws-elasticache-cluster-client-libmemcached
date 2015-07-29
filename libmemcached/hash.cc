/*  vim:expandtab:shiftwidth=2:tabstop=2:smarttab:
 * 
 *  Libmemcached library
 *
 *  Copyright (C) 2011 Data Differential, http://datadifferential.com/
 *  Copyright (C) 2006-2009 Brian Aker All rights reserved.
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

#include <sys/time.h>

#include <libmemcached/virtual_bucket.h>

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

uint32_t memcached_generate_hash_value(const char *key, size_t key_length, memcached_hash_t hash_algorithm)
{
  return libhashkit_digest(key, key_length, (hashkit_hash_algorithm_t)hash_algorithm);
}

static inline uint32_t generate_hash(const memcached_st *ptr, const char *key, size_t key_length)
{
  return hashkit_digest(&ptr->hashkit, key, key_length);
}

static uint32_t dispatch_host(const memcached_st *ptr, uint32_t hash)
{
  switch (ptr->distribution)
  {
  case MEMCACHED_DISTRIBUTION_CONSISTENT:
  case MEMCACHED_DISTRIBUTION_CONSISTENT_WEIGHTED:
  case MEMCACHED_DISTRIBUTION_CONSISTENT_KETAMA:
  case MEMCACHED_DISTRIBUTION_CONSISTENT_KETAMA_SPY:
    {
      uint32_t num= ptr->ketama.continuum_points_counter;
      WATCHPOINT_ASSERT(ptr->ketama.continuum);

      memcached_continuum_item_st *begin, *end, *left, *right, *middle;
      begin= left= ptr->ketama.continuum;
      end= right= ptr->ketama.continuum + num;

      while (left < right)
      {
        middle= left + (right - left) / 2;
        if (middle->value < hash)
          left= middle + 1;
        else
          right= middle;
      }
      if (right == end)
        right= begin;
      return right->index;
    }
  case MEMCACHED_DISTRIBUTION_MODULA:
    return hash % memcached_server_count(ptr);
  case MEMCACHED_DISTRIBUTION_RANDOM:
    return (uint32_t) random() % memcached_server_count(ptr);
  case MEMCACHED_DISTRIBUTION_VIRTUAL_BUCKET:
    {
      return memcached_virtual_bucket_get(ptr, hash);
    }
  default:
  case MEMCACHED_DISTRIBUTION_CONSISTENT_MAX:
    WATCHPOINT_ASSERT(0); /* We have added a distribution without extending the logic */
    return hash % memcached_server_count(ptr);
  }
  /* NOTREACHED */
}

/*
  One version is public and will not modify the distribution hash, the other will.
*/
static inline uint32_t _generate_hash_wrapper(const memcached_st *ptr, const char *key, size_t key_length)
{
  WATCHPOINT_ASSERT(memcached_server_count(ptr));

  if (memcached_server_count(ptr) == 1)
    return 0;

  if (ptr->flags.hash_with_namespace)
  {
    size_t temp_length= memcached_array_size(ptr->_namespace) + key_length;
    char temp[MEMCACHED_MAX_KEY];

    if (temp_length > MEMCACHED_MAX_KEY -1)
      return 0;

    strncpy(temp, memcached_array_string(ptr->_namespace), memcached_array_size(ptr->_namespace));
    strncpy(temp + memcached_array_size(ptr->_namespace), key, key_length);

    return generate_hash(ptr, temp, temp_length);
  }
  else
  {
    return generate_hash(ptr, key, key_length);
  }
}

static inline void _regen_for_auto_eject(memcached_st *ptr)
{
  if (_is_auto_eject_host(ptr) && ptr->ketama.next_distribution_rebuild)
  {
    struct timeval now;

    if (gettimeofday(&now, NULL) == 0 and
        now.tv_sec > ptr->ketama.next_distribution_rebuild)
    {
      run_distribution(ptr);
    }
  }
}

void memcached_autoeject(memcached_st *ptr)
{
  _regen_for_auto_eject(ptr);
}

/**
 * Compares the last time a polling operation was attempted (in an atomic way)
 * and if the time since last poll is > polling.threshold_secs then returns true
 */
static inline bool _is_time_to_poll(memcached_st *ptr)
{
  // if not memcached_st this is an error condition, so return false
  if (ptr == NULL) return false;

  time_t last_attempted = ptr->polling.last_attempted;

  time_t now = time(NULL);
  if (difftime(now, last_attempted) > ptr->polling.threshold_secs)
  {
    return true;
  }
  else 
  {
    // TODO: Add recovery action here (look at last_successful, potentially ignore prior result
  }

  return false;
}

/**
 * See internal function for documentation
 */
bool is_time_to_poll(memcached_st *ptr)
{
  return _is_time_to_poll(ptr);
}

/**
 * Parse the config version number from the configuration
 */
static inline uint64_t _get_config_version_number(const char *config)
{
  if (config == NULL)
  {
    errno = EINVAL;
    return 0;
  }

  char config_version_delimiter[] = "\n";
  int idx_config_version = strcspn(config, config_version_delimiter);
  char* config_ver_str = strndup(config, idx_config_version+1);
  uint64_t config_version = strtoull(config_ver_str, (char **)NULL, 10);
  
  free(config_ver_str);

  return config_version;
}

/**
 * Utility function make sure updating the current version number and config string
 * are both done atomically (with the assistance of the polling mutex)
 */
static inline void _update_current_version(memcached_st *ptr, uint64_t config_version_number, const char* config)
{
    if (ptr->polling.current_config != NULL)
    {
      free(ptr->polling.current_config);
    }
    ptr->polling.current_config = strdup(config);
    ptr->polling.current_config_version = config_version_number;
}

/**
 * A poor man's iterator through the array of server structures, returns index
 * of the next server from the current position.
 */
static inline int _get_server_position(const memcached_st *ptr, int cur_position)
{
  int position = ++cur_position;
  if (position >= (int) memcached_server_count(ptr))
  {
    // this is the wrap-around case, start from zero again
    position = 0;
  }

  return position;
}

/**
 * Actually responsible for retrieving configuration from memcached
 * 
 * 1. Round-Robin to find the next server to contact.
 * 2. Try 2x to get the config fro mthat server.
 * 3. As a last attempt, try to get config from the config endpoint
 * 
 * Return NULL if unable to get configuration
 */
static inline char *_config_get(memcached_st *ptr)
{
  char *result = NULL;
  int MAX_RETRY_COUNT = 3;
  int cur_position = ptr->polling.last_server_key;
  int retry_count;
  for (retry_count = 1; retry_count <= MAX_RETRY_COUNT; retry_count++)
  {
    // 1. Round-robin, which server should be contacted next
    int server_idx = _get_server_position(ptr, cur_position);
    memcached_server_instance_st server = memcached_server_instance_by_position(ptr, server_idx);

    memcached_server_st *config_server = (memcached_server_st *) server;

    if (retry_count == MAX_RETRY_COUNT)
    {
      // if on final try and use the config server
      config_server = memcached_config_server_fetch(ptr);
      // In case that all nodes in the cluster are replaced, we need to re-resolve
      // the configuration endpoint by DNS lookup. Since the config server doesn't
      // contain IP address, this call will do the DNS lookup using hostname
      reresolve_servers_in_client(&config_server, 1);
    }

    size_t value_length;
    uint32_t flags;
    memcached_return rr;
    char *config = memcached_config_get(config_server, ptr, &value_length, &flags, &rr);

    if (rr == MEMCACHED_SUCCESS)
    {
      result = config;
      // update index
      ptr->polling.last_server_key = server_idx;
      break;
    }
    else
    {
      cur_position = server_idx;

      if (config != NULL) free(config);
    }
  }

  return result;
}

static inline bool _apply_new_server_list(memcached_st *ptr, char *config)
{
  // parse configuration
  memcached_server_st *new_server_list = parse_memcached_configuration(config);    

  // apply changes to configuration
  memcached_return rr;
  rr = notify_server_list_update(ptr, new_server_list);
  memcached_server_list_free(new_server_list);
  if (rr == MEMCACHED_SUCCESS)
  {
    return true;
  }
    
  return false;
}

/**
 * Responsible for actually retrieving the conifguration and then notifying the server_list
 * with the updated information.
 */
static inline void _update_server_list(memcached_st *ptr)
{
  // atomically update the last_attempted field
  ptr->polling.last_attempted = time(NULL);
  
  // Call config_get, detect_change, apply_change
  char *config = _config_get(ptr);
  if (config == NULL)
  {
    return;
  }

  // set this field to false in error cases
  bool isUpdateSuccessful = true;

  // detect change
  // if strings don't match then check config version values, do nothing otherwise
  if (ptr->polling.current_config == NULL)
  {
    uint64_t config_version_number = _get_config_version_number(config);

    isUpdateSuccessful = _apply_new_server_list(ptr, config);
    if (isUpdateSuccessful)
    {
      _update_current_version(ptr, config_version_number, config);
    }
  }
  else if (strcmp(ptr->polling.current_config, config) != 0)
  {
    uint64_t config_version_number = _get_config_version_number(config);
    if (config_version_number > ptr->polling.current_config_version)
    {
      isUpdateSuccessful = _apply_new_server_list(ptr, config);
      if (isUpdateSuccessful)
      {
        _update_current_version(ptr, config_version_number, config);
      }
    }
  }

  if (isUpdateSuccessful) 
  {
    ptr->polling.last_successful = time(NULL);
  }

  free(config);

}

/**
 * See comment for _update_server_list for more information
 */
void update_server_list(memcached_st *ptr)
{
  _update_server_list(ptr);
}

memcached_return_t complete_dynamic_initialization(memcached_st *ptr, const char *config)
{
  if (config == NULL || ptr == NULL)
  {
    return MEMCACHED_INVALID_ARGUMENTS;
  }

  // update the recorded config
  uint64_t config_version_number = _get_config_version_number(config);
  if (config_version_number == 0 || errno == EINVAL)
  {
    // error in parsing the config version number from server, return
    // parse failure
    return MEMCACHED_PARSE_ERROR;
  }
  _update_current_version(ptr, config_version_number, config);

  // consider this initialization complete
  ptr->polling.last_successful = time(NULL);

  return MEMCACHED_SUCCESS;
}

inline uint32_t _memcached_generate_hash_with_redistribution(memcached_st *ptr, const char *key, size_t key_length, bool should_skip_polling)
{
  // only attempt periodic polling in dynamic mode
  if(!should_skip_polling and memcached_is_dynamic_client_mode(ptr))
  {
    // periodic polling touchpoint
    if (_is_time_to_poll(ptr)) 
    {
      _update_server_list(ptr);
    }
  }

  uint32_t hash= _generate_hash_wrapper(ptr, key, key_length);

  _regen_for_auto_eject(ptr);

  return dispatch_host(ptr, hash);
}

uint32_t memcached_generate_hash_with_redistribution(memcached_st *ptr, const char *key, size_t key_length)
{
  return _memcached_generate_hash_with_redistribution(ptr, key, key_length, false);
}

uint32_t memcached_generate_hash_with_redistribution_skip_polling(memcached_st *ptr, const char *key, size_t key_length)
{
  return _memcached_generate_hash_with_redistribution(ptr, key, key_length, true);
}

uint32_t memcached_generate_hash(const memcached_st *ptr, const char *key, size_t key_length)
{
  return dispatch_host(ptr, _generate_hash_wrapper(ptr, key, key_length));
}

const hashkit_st *memcached_get_hashkit(const memcached_st *ptr)
{
  return &ptr->hashkit;
}

memcached_return_t memcached_set_hashkit(memcached_st *self, hashkit_st *hashk)
{
  hashkit_free(&self->hashkit);
  hashkit_clone(&self->hashkit, hashk);

  return MEMCACHED_SUCCESS;
}

const char * libmemcached_string_hash(memcached_hash_t type)
{
  return libhashkit_string_hash((hashkit_hash_algorithm_t)type);
}
