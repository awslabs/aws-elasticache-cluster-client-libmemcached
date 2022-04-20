Name:      libmemcached
Summary:   memcached C library and command line tools
Version:   1.0.18
Release:   1
License:   BSD
Group:     System Environment/Libraries
URL:       http://launchpad.net/libmemcached
Source0:   http://download.tangent.org/libmemcached-%{version}.tar.gz

# For test suite
BuildRequires: bash
BuildRequires: binutils
BuildRequires: coreutils
BuildRequires: cpio
BuildRequires: cyrus-sasl-devel
BuildRequires: diffutils
BuildRequires: elfutils
BuildRequires: file
BuildRequires: findutils
BuildRequires: gawk
BuildRequires: gcc
BuildRequires: glibc
BuildRequires: glibc-common
BuildRequires: glibc-devel
BuildRequires: glibc-headers
BuildRequires: grep
BuildRequires: gzip
BuildRequires: libevent-devel
BuildRequires: libstdc++-devel
BuildRequires: libuuid-devel
BuildRequires: make
BuildRequires: memcached
BuildRequires: pkgconfig
BuildRequires: python-sphinx
BuildRequires: sed
BuildRequires: tar

BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)


%description
libmemcached, http://libmemcached.org/, is a C client library to the memcached server
(http://danga.com/memcached). It has been designed to be light on memory
usage, and provide full access to server side methods.

It also implements several command line tools:

memcat - Copy the value of a key to standard output.
memflush - Flush the contents of your servers.
memrm - Remove a key(s) from the serrver.
memstat - Dump the stats of your servers to standard output.
memslap - Generate testing loads on a memcached cluster.
memcp - Copy files to memcached servers.
memerror - Creates human readable messages from libmemecached error codes.
memcapable - Verify a memcached server for protocol behavior.
memexist - Check for the existance of a key.
memtouch - Update the expiration value of a key.


%package devel
Summary: Header files and development libraries for %{name}
Group: Development/Libraries
Requires: %{name} = %{version}-%{release}

%description devel
This package contains the header files and development libraries
for %{name}. If you like to develop programs using %{name}, 
you will need to install %{name}-devel.


%prep
%setup -q

%{__mkdir} examples

%build
%configure
%{__make} %{?_smp_mflags}


%install
%{__rm} -rf %{buildroot}
%{__make} install  DESTDIR="%{buildroot}" AM_INSTALL_PROGRAM_FLAGS=""


%check
# test suite cannot run in mock (same port use for memcache server on all arch)
# 1 test seems to fail.. 
# %{__make} check


%clean
%{__rm} -rf %{buildroot}


%post -p /sbin/ldconfig


%postun -p /sbin/ldconfig
 

%files
%defattr (-,root,root,-) 
%doc AUTHORS COPYING NEWS README THANKS TODO
%{_bindir}/mem*
%exclude %{_libdir}/libmemcached.la
%exclude %{_libdir}/libhashkit.la
%exclude %{_libdir}/libmemcachedutil.la
%exclude %{_libdir}/libmemcached.a
%exclude %{_libdir}/libhashkit.a
%exclude %{_libdir}/libmemcachedutil.a
%{_libdir}/libhashkit.so.2.0.0
%{_libdir}/libmemcached.so.11.0.0
%{_libdir}/libmemcachedutil.so.2.0.0
%{_libdir}/libhashkit.so.2
%{_libdir}/libmemcached.so.11
%{_libdir}/libmemcachedutil.so.2
%{_mandir}/man1/memaslap.1.gz
%{_mandir}/man1/memcapable.1.gz
%{_mandir}/man1/memcat.1.gz
%{_mandir}/man1/memcp.1.gz
%{_mandir}/man1/memdump.1.gz
%{_mandir}/man1/memerror.1.gz
%{_mandir}/man1/memexist.1.gz
%{_mandir}/man1/memflush.1.gz
%{_mandir}/man1/memparse.1.gz
%{_mandir}/man1/memping.1.gz
%{_mandir}/man1/memrm.1.gz
%{_mandir}/man1/memslap.1.gz
%{_mandir}/man1/memstat.1.gz
%{_mandir}/man1/memtouch.1.gz


%files devel
%defattr (-,root,root,-) 
%doc examples
%{_datadir}/aclocal/ax_libmemcached.m4
%{_includedir}/libhashkit/hashkit.h
%{_includedir}/libhashkit-1.0/algorithm.h
%{_includedir}/libhashkit-1.0/behavior.h
%{_includedir}/libhashkit-1.0/configure.h
%{_includedir}/libhashkit-1.0/digest.h
%{_includedir}/libhashkit-1.0/function.h
%{_includedir}/libhashkit-1.0/has.h
%{_includedir}/libhashkit-1.0/hashkit.h
%{_includedir}/libhashkit-1.0/hashkit.hpp
%{_includedir}/libhashkit-1.0/str_algorithm.h
%{_includedir}/libhashkit-1.0/strerror.h
%{_includedir}/libhashkit-1.0/types.h
%{_includedir}/libhashkit-1.0/visibility.h

%{_includedir}/libmemcachedutil-1.0/util.h
%{_includedir}/libmemcachedutil-1.0/flush.h
%{_includedir}/libmemcachedutil-1.0/pid.h
%{_includedir}/libmemcachedutil-1.0/ping.h
%{_includedir}/libmemcachedutil-1.0/ostream.hpp
%{_includedir}/libmemcachedutil-1.0/pool.h
%{_includedir}/libmemcachedutil-1.0/version.h

%{_includedir}/libmemcached/memcached.h
%{_includedir}/libmemcached/memcached.hpp
%{_includedir}/libmemcached/util.h

%{_includedir}/libmemcached-1.0/alloc.h
%{_includedir}/libmemcached-1.0/allocators.h
%{_includedir}/libmemcached-1.0/analyze.h
%{_includedir}/libmemcached-1.0/auto.h
%{_includedir}/libmemcached-1.0/basic_string.h
%{_includedir}/libmemcached-1.0/behavior.h
%{_includedir}/libmemcached-1.0/callback.h
%{_includedir}/libmemcached-1.0/callbacks.h
%{_includedir}/libmemcached-1.0/configure.h
%{_includedir}/libmemcached-1.0/defaults.h
%{_includedir}/libmemcached-1.0/delete.h
%{_includedir}/libmemcached-1.0/deprecated_types.h
%{_includedir}/libmemcached-1.0/dump.h
%{_includedir}/libmemcached-1.0/error.h
%{_includedir}/libmemcached-1.0/exception.hpp
%{_includedir}/libmemcached-1.0/exist.h
%{_includedir}/libmemcached-1.0/fetch.h
%{_includedir}/libmemcached-1.0/flush.h
%{_includedir}/libmemcached-1.0/flush_buffers.h
%{_includedir}/libmemcached-1.0/get.h
%{_includedir}/libmemcached-1.0/hash.h
%{_includedir}/libmemcached-1.0/limits.h
%{_includedir}/libmemcached-1.0/memcached.h
%{_includedir}/libmemcached-1.0/memcached.hpp
%{_includedir}/libmemcached-1.0/options.h
%{_includedir}/libmemcached-1.0/parse.h
%{_includedir}/libmemcached-1.0/platform.h
%{_includedir}/libmemcached-1.0/quit.h
%{_includedir}/libmemcached-1.0/result.h
%{_includedir}/libmemcached-1.0/return.h
%{_includedir}/libmemcached-1.0/sasl.h
%{_includedir}/libmemcached-1.0/server.h
%{_includedir}/libmemcached-1.0/server_list.h
%{_includedir}/libmemcached-1.0/stats.h
%{_includedir}/libmemcached-1.0/storage.h
%{_includedir}/libmemcached-1.0/strerror.h
%{_includedir}/libmemcached-1.0/struct/allocator.h
%{_includedir}/libmemcached-1.0/struct/analysis.h
%{_includedir}/libmemcached-1.0/struct/callback.h
%{_includedir}/libmemcached-1.0/struct/memcached.h
%{_includedir}/libmemcached-1.0/struct/result.h
%{_includedir}/libmemcached-1.0/struct/sasl.h
%{_includedir}/libmemcached-1.0/struct/server.h
%{_includedir}/libmemcached-1.0/struct/stat.h
%{_includedir}/libmemcached-1.0/struct/string.h
%{_includedir}/libmemcached-1.0/struct/tls.h
%{_includedir}/libmemcached-1.0/tls.h
%{_includedir}/libmemcached-1.0/touch.h
%{_includedir}/libmemcached-1.0/triggers.h
%{_includedir}/libmemcached-1.0/types.h
%{_includedir}/libmemcached-1.0/types/behavior.h
%{_includedir}/libmemcached-1.0/types/callback.h
%{_includedir}/libmemcached-1.0/types/connection.h
%{_includedir}/libmemcached-1.0/types/hash.h
%{_includedir}/libmemcached-1.0/types/return.h
%{_includedir}/libmemcached-1.0/types/server_distribution.h
%{_includedir}/libmemcached-1.0/verbosity.h
%{_includedir}/libmemcached-1.0/version.h
%{_includedir}/libmemcached-1.0/visibility.h
%{_includedir}/libhashkit-1.0/string.h
%{_includedir}/libmemcached-1.0/encoding_key.h

%{_libdir}/libhashkit.so
%{_libdir}/libmemcached.so
%{_libdir}/libmemcachedutil.so
%{_libdir}/pkgconfig/libmemcached.pc
%{_mandir}/man3/hashkit_clone.3.gz
%{_mandir}/man3/hashkit_crc32.3.gz
%{_mandir}/man3/hashkit_create.3.gz
%{_mandir}/man3/hashkit_fnv1_32.3.gz
%{_mandir}/man3/hashkit_fnv1_64.3.gz
%{_mandir}/man3/hashkit_fnv1a_32.3.gz
%{_mandir}/man3/hashkit_fnv1a_64.3.gz
%{_mandir}/man3/hashkit_free.3.gz
%{_mandir}/man3/hashkit_functions.3.gz
%{_mandir}/man3/hashkit_hsieh.3.gz
%{_mandir}/man3/hashkit_is_allocated.3.gz
%{_mandir}/man3/hashkit_jenkins.3.gz
%{_mandir}/man3/hashkit_md5.3.gz
%{_mandir}/man3/hashkit_murmur.3.gz
%{_mandir}/man3/hashkit_value.3.gz
%{_mandir}/man3/libhashkit.3.gz
%{_mandir}/man3/libmemcached.3.gz
%{_mandir}/man3/libmemcached_check_configuration.3.gz
%{_mandir}/man3/libmemcached_configuration.3.gz
%{_mandir}/man3/libmemcached_examples.3.gz
%{_mandir}/man3/libmemcachedutil.3.gz
%{_mandir}/man3/memcached.3.gz
%{_mandir}/man3/memcached_add.3.gz
%{_mandir}/man3/memcached_add_by_key.3.gz
%{_mandir}/man3/memcached_analyze.3.gz
%{_mandir}/man3/memcached_append.3.gz
%{_mandir}/man3/memcached_append_by_key.3.gz
%{_mandir}/man3/memcached_behavior_get.3.gz
%{_mandir}/man3/memcached_behavior_set.3.gz
%{_mandir}/man3/memcached_callback_get.3.gz
%{_mandir}/man3/memcached_callback_set.3.gz
%{_mandir}/man3/memcached_cas.3.gz
%{_mandir}/man3/memcached_cas_by_key.3.gz
%{_mandir}/man3/memcached_clone.3.gz
%{_mandir}/man3/memcached_create.3.gz
%{_mandir}/man3/memcached_decrement.3.gz
%{_mandir}/man3/memcached_decrement_with_initial.3.gz
%{_mandir}/man3/memcached_delete.3.gz
%{_mandir}/man3/memcached_delete_by_key.3.gz
%{_mandir}/man3/memcached_destroy_sasl_auth_data.3.gz
%{_mandir}/man3/memcached_dump.3.gz
%{_mandir}/man3/memcached_fetch.3.gz
%{_mandir}/man3/memcached_fetch_execute.3.gz
%{_mandir}/man3/memcached_fetch_result.3.gz
%{_mandir}/man3/memcached_flush_buffers.3.gz
%{_mandir}/man3/memcached_free.3.gz
%{_mandir}/man3/memcached_generate_hash.3.gz
%{_mandir}/man3/memcached_generate_hash_value.3.gz
%{_mandir}/man3/memcached_ssl_context_get_error.3.gz
%{_mandir}/man3/_memcached_free_ssl_ctx.3.gz
%{_mandir}/man3/memcached_free_ssl_ctx.3.gz
%{_mandir}/man3/memcached_set_ssl_context.3.gz
%{_mandir}/man3/memcached_create_and_set_ssl_context.3.gz
%{_mandir}/man3/memcached_get_ssl_context_copy.3.gz
%{_mandir}/man3/memcached_get.3.gz
%{_mandir}/man3/memcached_get_by_key.3.gz
%{_mandir}/man3/memcached_get_memory_allocators.3.gz
%{_mandir}/man3/memcached_get_sasl_callbacks.3.gz
%{_mandir}/man3/memcached_get_user_data.3.gz
%{_mandir}/man3/memcached_increment.3.gz
%{_mandir}/man3/memcached_increment_with_initial.3.gz
%{_mandir}/man3/memcached_lib_version.3.gz
%{_mandir}/man3/memcached_mget.3.gz
%{_mandir}/man3/memcached_mget_by_key.3.gz
%{_mandir}/man3/memcached_mget_execute.3.gz
%{_mandir}/man3/memcached_mget_execute_by_key.3.gz
%{_mandir}/man3/memcached_pool_behavior_get.3.gz
%{_mandir}/man3/memcached_pool_behavior_set.3.gz
%{_mandir}/man3/memcached_pool_create.3.gz
%{_mandir}/man3/memcached_pool_destroy.3.gz
%{_mandir}/man3/memcached_pool_pop.3.gz
%{_mandir}/man3/memcached_pool_push.3.gz
%{_mandir}/man3/memcached_pool_fetch.3.gz
%{_mandir}/man3/memcached_pool_release.3.gz
%{_mandir}/man3/memcached_pool_st.3.gz
%{_mandir}/man3/memcached_pool.3.gz
%{_mandir}/man3/memcached_prepend.3.gz
%{_mandir}/man3/memcached_prepend_by_key.3.gz
%{_mandir}/man3/memcached_quit.3.gz
%{_mandir}/man3/memcached_replace.3.gz
%{_mandir}/man3/memcached_replace_by_key.3.gz
%{_mandir}/man3/memcached_sasl_set_auth_data.3.gz
%{_mandir}/man3/memcached_server_add.3.gz
%{_mandir}/man3/memcached_server_count.3.gz
%{_mandir}/man3/memcached_server_cursor.3.gz
%{_mandir}/man3/memcached_server_list.3.gz
%{_mandir}/man3/memcached_server_list_append.3.gz
%{_mandir}/man3/memcached_server_list_count.3.gz
%{_mandir}/man3/memcached_server_list_free.3.gz
%{_mandir}/man3/memcached_server_push.3.gz
%{_mandir}/man3/memcached_servers_parse.3.gz
%{_mandir}/man3/memcached_set.3.gz
%{_mandir}/man3/memcached_set_by_key.3.gz
%{_mandir}/man3/memcached_set_memory_allocators.3.gz
%{_mandir}/man3/memcached_set_sasl_callbacks.3.gz
%{_mandir}/man3/memcached_set_user_data.3.gz
%{_mandir}/man3/memcached_stat.3.gz
%{_mandir}/man3/memcached_stat_execute.3.gz
%{_mandir}/man3/memcached_stat_get_keys.3.gz
%{_mandir}/man3/memcached_last_error_message.3.gz
%{_mandir}/man3/memcached_stat_get_value.3.gz
%{_mandir}/man3/memcached_stat_servername.3.gz
%{_mandir}/man3/memcached_strerror.3.gz
%{_mandir}/man3/memcached_exist.3.gz
%{_mandir}/man3/memcached_exist_by_key.3.gz
%{_mandir}/man3/memcached_touch.3.gz
%{_mandir}/man3/memcached_touch_by_key.3.gz
%{_mandir}/man3/memcached_verbosity.3.gz
%{_mandir}/man3/memcached_version.3.gz



%changelog
* Tue May  22 2012 Brian Aker <brian@tangent.org> - 1.0.8

* Fri Jan  8 2010 Brian Aker <brian@tangent.org> - 0.37
- Modified to be explicit in install include files. 

* Sat Apr 25 2009 Remi Collet <rpms@famillecollet.com> - 0.28
- Initial RPM from Brian Aker spec
- create -devel subpackage
- add %%post %%postun %%check section

