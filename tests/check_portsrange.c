#include <check.h>
#include "../src/netcat.h"

/* Tests that the port range created by netcat_ports_init is empty */
START_TEST(test_empty)
{
  nc_ports_t ports = netcat_ports_init();
  ck_assert_int_eq(netcat_ports_count(ports), 0);
}
END_TEST

/* Tests the behavior for a single port range */
START_TEST(test_single_range)
{
  nc_ports_t ports = netcat_ports_init();
  netcat_ports_insert(ports, 2000, 2999);
  ck_assert_int_eq(netcat_ports_count(ports), 1000);
}
END_TEST

/* Tests the behavior for two non overlapping port ranges */
START_TEST(test_disjoint_ranges)
{
  nc_ports_t ports = netcat_ports_init();
  netcat_ports_insert(ports, 2000, 2999);
  netcat_ports_insert(ports, 4000, 3999);
  ck_assert_int_eq(netcat_ports_count(ports), 2000);
}
END_TEST

int main (void)
{
  int number_failed;
  Suite *s = suite_create("portsrange");
  TCase *tc_core = tcase_create("main");
  tcase_add_test(tc_core, test_empty);
  tcase_add_test(tc_core, test_single_range);
  tcase_add_test(tc_core, test_disjoint_ranges);
  suite_add_tcase(s, tc_core);
  SRunner *sr = srunner_create(s);
  srunner_run_all(sr, CK_NORMAL);
  number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
