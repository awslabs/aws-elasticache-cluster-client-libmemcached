# aws-elasticache-cluster-client-libmemcached

Libmemcached library support for Amazon ElastiCache Memcached Cluster client for PHP. The client is available at https://github.com/awslabs/aws-elasticache-cluster-client-memcached-for-php

To compile the libmemcached library

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

> ../configure --prefix=\<libmemcached-install-directory\> --with-pic

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
