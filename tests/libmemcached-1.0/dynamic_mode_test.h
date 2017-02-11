
#pragma once

#include <tests/libmemcached-1.0/memcached_get.h>

test_return_t config_get_test(memcached_st *);

test_return_t remove_node_test(memcached_st *ptr);

test_return_t add_node_test(memcached_st *ptr);

test_return_t replace_node_test(memcached_st *ptr);

test_return_t polling_test(memcached_st *ptr);

test_st dynamic_mode_test_TESTS[] ={
  {"config_get_test", false, (test_callback_fn*)config_get_test},
  {"remove_node_test", false, (test_callback_fn*)remove_node_test},
  {"add_node_test", false, (test_callback_fn*)add_node_test},
  {"replace_node_test", false, (test_callback_fn*)replace_node_test},
  {"polling_test", false, (test_callback_fn*)polling_test },
  {0, 0, 0}
};


collection_st collection[] ={
  {"dynamic_mode_test", 0, 0, dynamic_mode_test_TESTS},
  {0, 0, 0, 0}
};
