default: memc_client

memc_client: client_test.cpp
	g++ $^ -g -L/home/ec2-user/libmemcached/lib -lmemcached -lmemcachedutil -I/home/ec2-user/libmemcached/include -L/usr/local/ssl/lib -lssl -lcrypto -I/usr/local/ssl/include -o $@

.PHONY: clean
clean:
	rm -f *.o tar rmt client_test client_test.h core
