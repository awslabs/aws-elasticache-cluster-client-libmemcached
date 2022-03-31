/*  vim:expandtab:shiftwidth=2:tabstop=2:smarttab:
 * 
 *  Libmemcached Client and Server 
 *
 *  Copyright (C) 2012 Data Differential, http://datadifferential.com/
 *  Copyright (C) 2006-2009 Brian Aker
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
 */


#pragma once

#include "tests/libmemcached_test_container.h"

static void *world_create(libtest::server_startup_st& servers, test_return_t& error)
{
  SKIP_UNLESS(libtest::has_libmemcached());

  if (servers.sasl())
  {
    SKIP_UNLESS(libtest::has_libmemcached_sasl());

    // Assume we are running under valgrind, and bail
    if (getenv("LOG_COMPILER"))
    {
      error= TEST_SKIPPED;
      return NULL;
    }
  }

    if (servers.ssl())
    {
        SKIP_UNLESS(libtest::has_libmemcached_ssl());

        // Assume we are running under valgrind, and bail
        if (getenv("LOG_COMPILER"))
        {
            error= TEST_SKIPPED;
            return NULL;
        }
    }

  for (uint32_t x= 0; x < servers.servers_to_run(); x++)
  {
    in_port_t port= libtest::get_free_port();

    if (servers.sasl())
    {
      if (server_startup(servers, "memcached-sasl", port, NULL) == false)
      {
        error= TEST_SKIPPED;
        return NULL;
      }
    } else if (servers.ssl()) {
        std::stringstream cert_file; ;
        std::stringstream private_key_file;
        char *tls_folder = "/tls";
        char *ssl_path = getenv("PWD");
        cert_file << "ssl_chain_cert=" << ssl_path << tls_folder << "/memc.crt";
        private_key_file << "ssl_key=" << ssl_path << tls_folder << "/memc.key";
        const char *argv[] = {"-Z", "-o", cert_file.str().c_str(), "-o", private_key_file.str().c_str()};
        if (server_startup(servers, "memcached", port, argv) == false)
        {
            error= TEST_SKIPPED;
            return NULL;
        }
    }
    else
    {

    }
  }

  libmemcached_test_container_st *global_container= new libmemcached_test_container_st(servers);

  return global_container;
}

static bool world_destroy(void *object)
{
  libmemcached_test_container_st *container= (libmemcached_test_container_st *)object;
#if 0
#if defined(LIBMEMCACHED_WITH_SASL_SUPPORT) && LIBMEMCACHED_WITH_SASL_SUPPORT
  if (LIBMEMCACHED_WITH_SASL_SUPPORT)
  {
    sasl_done();
  }
#endif
#endif

  delete container;

  return TEST_SUCCESS;
}

typedef test_return_t (*libmemcached_test_callback_fn)(memcached_st *);

#include "tests/runner.h"
