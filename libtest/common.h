/*  vim:expandtab:shiftwidth=2:tabstop=2:smarttab:
 *
 *  Data Differential YATL (i.e. libtest)  library
 *
 *  Copyright (C) 2012 Data Differential, http://datadifferential.com/
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are
 *  met:
 *
 *      * Redistributions of source code must retain the above copyright
 *  notice, this list of conditions and the following disclaimer.
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
/*
  Common include file for libtest
*/

#pragma once

#include <cassert>
#include <cerrno>
#include <cstdlib>
#include <sstream>
#include <string>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_SYS_TIME_H
# include <sys/time.h>
#endif

#ifdef HAVE_SYS_WAIT_H
# include <sys/wait.h>
#endif

#ifdef HAVE_SYS_RESOURCE_H 
# include <sys/resource.h> 
#endif
 
#ifdef HAVE_FNMATCH_H
# include <fnmatch.h>
#endif

#ifdef HAVE_ARPA_INET_H
# include <arpa/inet.h>
#endif

#if defined(WIN32)
# include "win32/wrappers.h"
# define get_socket_errno() WSAGetLastError()
#else
# ifdef HAVE_UNISTD_H
#  include <unistd.h>
# endif
# define INVALID_SOCKET -1
# define SOCKET_ERROR -1
# define closesocket(a) close(a)
# define get_socket_errno() errno
#endif

#include <libtest/test.hpp>

#include <libtest/is_pid.hpp>

#include <libtest/gearmand.h>
#include <libtest/blobslap_worker.h>
#include <libtest/memcached.h>
#include <libtest/drizzled.h>

#include <libtest/libtool.hpp>
#include <libtest/killpid.h>
#include <libtest/signal.h>
#include <libtest/dns.hpp>
#include <libtest/formatter.hpp>
#include <libtest/dynamic_mode.h>

struct FreeFromVector
{
  template <class T>
    void operator() ( T* ptr) const
    {
      if (ptr)
      {
        free(ptr);
        ptr= NULL;
      }
    }
};

struct DeleteFromVector
{
  template <class T>
    void operator() ( T* ptr) const
    {
      delete ptr;
      ptr= NULL;
    }
};
