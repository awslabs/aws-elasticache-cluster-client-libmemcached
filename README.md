# aws-elasticache-cluster-client-libmemcached

Libmemcached library support for Amazon ElastiCache Memcached Cluster client for PHP. The client is available at https://github.com/awslabs/aws-elasticache-cluster-client-memcached-for-php

### Prerequests libraries
- OpenSSL (unless TLS support is disabled by ./configure --disable-tls).
- SASL (libsasl2, unless SASL support is disabled by ./configure --disable-sasl).

### compile the libmemcached library

1) Launch the instance

2) Install the library dependencies.

a) On Amazon Linux 201509 AMI

> sudo yum install gcc gcc-c++ autoconf libevent-devel 

b) On Ubuntu 14.04 AMI

> sudo apt-get update

> sudo apt-get install libevent-dev gcc g++ make autoconf libsasl2-dev

3) Pull the repository and compile the code

> git clone https://github.com/awslabs/aws-elasticache-cluster-client-libmemcached.git

> cd aws-elasticache-cluster-client-libmemcached

> touch configure.ac aclocal.m4 configure Makefile.am Makefile.in

> mkdir BUILD

> cd BUILD

> ../configure --prefix=\<libmemcached-install-directory\> --with-pic --disable-sasl 

If running ../configure fails to find *libssl* (OpenSSL library) it may be necessary to tweak the PKG_CONFIG_PATH environment variable:
> PKG_CONFIG_PATH=/path/to/openssl/lib/pkgconfig ../configure --prefix=\<libmemcached-install-directory\> --with-pic --disable-sasl

Alternately, if you are not using TLS, you can disable it by running:
> ../configure --prefix=\<libmemcached-install-directory\> --with-pic --disable-sasl --disable-tls

> make

> sudo make install

Then track the installation directory path for libmemcached, as that will be needed to compile PHP memcached client. 

Note: if you want to run the ElastiCache memcached PHP client on AMIs other than Amazon Linux, statically link the libmemcached library in the PHP-memcached client compilation, which will generate memcached.so binary extension which should be portable across Linux platforms. 

# Resources
---------
 * [Github link] (https://github.com/awslabs/aws-elasticache-cluster-client-libmemcached)
 * [AmazonElastiCache Auto Discovery](http://docs.amazonwebservices.com/AmazonElastiCache/latest/UserGuide/AutoDiscovery.html)
 * [php-memcached] (https://github.com/php-memcached-dev/php-memcached)
 * [libmemcached](http://libmemcached.org/libMemcached.html)
 * [memcached](http://www.danga.com/memcached/)
 * [igbinary](https://github.com/phadej/igbinary/)
