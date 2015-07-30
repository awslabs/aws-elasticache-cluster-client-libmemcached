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


#pragma once

/* Public defines */
#define MEMCACHED_DEFAULT_PORT 11211
#define MEMCACHED_POINTS_PER_SERVER 100
#define MEMCACHED_POINTS_PER_SERVER_KETAMA 160
#define MEMCACHED_CONTINUUM_SIZE MEMCACHED_POINTS_PER_SERVER*100 /* This would then set max hosts to 100 */
#define MEMCACHED_STRIDE 4
#define MEMCACHED_DEFAULT_TIMEOUT 5000
#define MEMCACHED_DEFAULT_CONNECT_TIMEOUT 4000
#define MEMCACHED_CONTINUUM_ADDITION 10 /* How many extra slots we should build for in the continuum */
#define MEMCACHED_EXPIRATION_NOT_ADD 0xffffffffU
#define MEMCACHED_SERVER_FAILURE_LIMIT 5
#define MEMCACHED_SERVER_FAILURE_RETRY_TIMEOUT 2
#define MEMCACHED_SERVER_FAILURE_DEAD_TIMEOUT 0
#define MEMCACHED_POLLING_TIMEOUT_SECS 60 /* Default time between polling for configuration changes */


