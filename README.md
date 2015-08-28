# aws-elasticache-cluster-client-libmemcached

Libmemcached library support for Amazon ElastiCache Memcached Cluster client for PHP. The client is available at https://github.com/awslabs/aws-elasticache-cluster-client-memcached-for-php

To compile the libmemcached library (verified on Amazon Linux 201503 AMI)

1) Launch the instance
2) Install the library dependencies.

> sudo yum install gcc gcc-c++ autoconf libevent-devel 

3) Under the aws-elasticache-cluster-client-libmemcached/ directory, run the following commands

> configure

> make

Note: if compilation fails due to warnings being treated as errors, update Makefile by removing "-Werror" from compiler flags, and re-run "make"

> sudo make install

Then track the installation directory path for libmemcached, as that will be needed to compile PHP memcached client. 

Note: if you want to run the ElastiCache memcached PHP client on AMIs other than Amazon Linux, statically link the libmemcached library in the PHP-memcached clent compilation, which will generate memcached.so binary extension which should be portable across Linux platforms. 

# Resources
---------
 * [Github link] (https://github.com/awslabs/aws-elasticache-cluster-client-libmemcached)
 * [AmazonElastiCache Auto Discovery](http://docs.amazonwebservices.com/AmazonElastiCache/latest/UserGuide/AutoDiscovery.html)
 * [php-memcached] (https://github.com/php-memcached-dev/php-memcached)
 * [libmemcached](http://libmemcached.org/libMemcached.html)
 * [memcached](http://www.danga.com/memcached/)
 * [igbinary](https://github.com/phadej/igbinary/)
