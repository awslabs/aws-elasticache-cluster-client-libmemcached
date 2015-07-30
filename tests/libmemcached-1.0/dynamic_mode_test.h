
#pragma once
test_return_t config_get_test(memcached_st *);

test_return_t remove_node_test(memcached_st *ptr);

test_return_t add_node_test(memcached_st *ptr);

test_return_t replace_node_test(memcached_st *ptr);

test_return_t polling_test(memcached_st *ptr);
