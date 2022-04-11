/*  vim:expandtab:shiftwidth=2:tabstop=2:smarttab:
 * 
 *  Libmemcached library
 *
 *  Copyright (C) 2011 Data Differential, http://datadifferential.com/ 
 *  All rights reserved.
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


#pragma once

enum memcached_behavior_t {
  MEMCACHED_BEHAVIOR_NO_BLOCK,
  MEMCACHED_BEHAVIOR_TCP_NODELAY,
  MEMCACHED_BEHAVIOR_HASH,
  MEMCACHED_BEHAVIOR_KETAMA,
  MEMCACHED_BEHAVIOR_SOCKET_SEND_SIZE,
  MEMCACHED_BEHAVIOR_SOCKET_RECV_SIZE,
  MEMCACHED_BEHAVIOR_CACHE_LOOKUPS,
  MEMCACHED_BEHAVIOR_SUPPORT_CAS,
  MEMCACHED_BEHAVIOR_POLL_TIMEOUT,
  MEMCACHED_BEHAVIOR_DISTRIBUTION,
  MEMCACHED_BEHAVIOR_BUFFER_REQUESTS,
  MEMCACHED_BEHAVIOR_USER_DATA,
  MEMCACHED_BEHAVIOR_SORT_HOSTS,
  MEMCACHED_BEHAVIOR_VERIFY_KEY,
  MEMCACHED_BEHAVIOR_CONNECT_TIMEOUT,
  MEMCACHED_BEHAVIOR_RETRY_TIMEOUT,
  MEMCACHED_BEHAVIOR_KETAMA_WEIGHTED,
  MEMCACHED_BEHAVIOR_KETAMA_HASH,
  MEMCACHED_BEHAVIOR_BINARY_PROTOCOL,
  MEMCACHED_BEHAVIOR_SND_TIMEOUT,
  MEMCACHED_BEHAVIOR_RCV_TIMEOUT,
  MEMCACHED_BEHAVIOR_SERVER_FAILURE_LIMIT,
  MEMCACHED_BEHAVIOR_IO_MSG_WATERMARK,
  MEMCACHED_BEHAVIOR_IO_BYTES_WATERMARK,
  MEMCACHED_BEHAVIOR_IO_KEY_PREFETCH,
  MEMCACHED_BEHAVIOR_HASH_WITH_PREFIX_KEY,
  MEMCACHED_BEHAVIOR_NOREPLY,
  MEMCACHED_BEHAVIOR_USE_UDP,
  MEMCACHED_BEHAVIOR_AUTO_EJECT_HOSTS,
  MEMCACHED_BEHAVIOR_NUMBER_OF_REPLICAS,
  MEMCACHED_BEHAVIOR_RANDOMIZE_REPLICA_READ,
  MEMCACHED_BEHAVIOR_CORK,
  MEMCACHED_BEHAVIOR_TCP_KEEPALIVE,
  MEMCACHED_BEHAVIOR_TCP_KEEPIDLE,
  MEMCACHED_BEHAVIOR_LOAD_FROM_FILE,
  MEMCACHED_BEHAVIOR_REMOVE_FAILED_SERVERS,
  MEMCACHED_BEHAVIOR_DEAD_TIMEOUT,
  MEMCACHED_BEHAVIOR_SERVER_TIMEOUT_LIMIT,
  MEMCACHED_BEHAVIOR_CLIENT_MODE,
  MEMCACHED_BEHAVIOR_DYNAMIC_POLLING_THRESHOLD_SECS,
  MEMCACHED_BEHAVIOR_USE_TLS,
  MEMCACHED_BEHAVIOR_MAX
};

#ifndef __cplusplus
typedef enum memcached_behavior_t memcached_behavior_t;
#endif
