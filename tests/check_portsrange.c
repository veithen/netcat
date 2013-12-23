/*
 * check_portsrange.c -- unit tests for portsrange.c
 * Part of the GNU netcat project
 *
 * Author: Andreas Veithen <andreas.veithen@gmail.com>
 * Copyright (C) 2013  Andreas Veithen
 */

/***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 ***************************************************************************/

#include <check.h>
#include "../src/netcat.h"

/* Redeclare the private struct (see portsrange.c) here so that we can access it */
struct nc_ports_st {
  int start;
  int end;
  struct nc_ports_st *next;
};

/* Tests the behavior for an empty port range */
START_TEST(test_empty)
{
  nc_ports_t ports = NULL;
  ck_assert_int_eq(netcat_ports_count(ports), 0);
  // This assertion was not satisfied in previous 0.8 versions from trunk
  ck_assert(!netcat_ports_isset(ports, 0));
  ck_assert_int_eq(netcat_ports_next(ports, 0), 0);
}
END_TEST

/* Tests the behavior for a single port range */
START_TEST(test_single_range)
{
  nc_ports_t ports = NULL;
  netcat_ports_insert(&ports, 2000, 2999);
  ck_assert_int_eq(ports->start, 2000);
  ck_assert_int_eq(ports->end, 3000);
  ck_assert(!ports->next);
  ck_assert_int_eq(netcat_ports_count(ports), 1000);
  ck_assert(!netcat_ports_isset(ports, 1999));
  ck_assert(netcat_ports_isset(ports, 2000));
  ck_assert(netcat_ports_isset(ports, 2999));
  ck_assert(!netcat_ports_isset(ports, 3000));
}
END_TEST

/* Tests the behavior for two non overlapping port ranges */
START_TEST(test_disjoint_ranges)
{
  nc_ports_t ports = NULL;
  netcat_ports_insert(&ports, 2000, 2999);
  netcat_ports_insert(&ports, 4000, 4999);
  ck_assert_int_eq(ports->start, 2000);
  ck_assert_int_eq(ports->end, 3000);
  ck_assert(!!ports->next);
  ck_assert_int_eq(ports->next->start, 4000);
  ck_assert_int_eq(ports->next->end, 5000);
  ck_assert(!ports->next->next);
  ck_assert_int_eq(netcat_ports_count(ports), 2000);
  ck_assert(!netcat_ports_isset(ports, 1999));
  ck_assert(netcat_ports_isset(ports, 2000));
  ck_assert(netcat_ports_isset(ports, 2999));
  ck_assert(!netcat_ports_isset(ports, 3000));
  ck_assert(!netcat_ports_isset(ports, 3999));
  ck_assert(netcat_ports_isset(ports, 4000));
  ck_assert(netcat_ports_isset(ports, 4999));
  ck_assert(!netcat_ports_isset(ports, 5000));
}
END_TEST

/* Tests the behavior for two non overlapping adjacent ranges */
START_TEST(test_adjacent_ranges)
{
  nc_ports_t ports = NULL;
  netcat_ports_insert(&ports, 2000, 2999);
  netcat_ports_insert(&ports, 3000, 3999);
  ck_assert_int_eq(ports->start, 2000);
  ck_assert_int_eq(ports->end, 4000);
  ck_assert(!ports->next);
  ck_assert_int_eq(netcat_ports_count(ports), 2000);
}
END_TEST

START_TEST(test_overlapping_ranges_1)
{
  nc_ports_t ports = NULL;
  netcat_ports_insert(&ports, 2000, 2999);
  netcat_ports_insert(&ports, 2500, 3499);
  ck_assert_int_eq(ports->start, 2000);
  ck_assert_int_eq(ports->end, 3500);
  ck_assert(!ports->next);
  ck_assert_int_eq(netcat_ports_count(ports), 1500);
}
END_TEST

START_TEST(test_overlapping_ranges_2)
{
  nc_ports_t ports = NULL;
  netcat_ports_insert(&ports, 2500, 3499);
  netcat_ports_insert(&ports, 2000, 2999);
  ck_assert_int_eq(ports->start, 2000);
  ck_assert_int_eq(ports->end, 3500);
  ck_assert(!ports->next);
  ck_assert_int_eq(netcat_ports_count(ports), 1500);
}
END_TEST

START_TEST(test_overlapping_ranges_3)
{
  nc_ports_t ports = NULL;
  netcat_ports_insert(&ports, 2000, 2999);
  netcat_ports_insert(&ports, 1000, 3999);
  ck_assert_int_eq(ports->start, 1000);
  ck_assert_int_eq(ports->end, 4000);
  ck_assert(!ports->next);
  ck_assert_int_eq(netcat_ports_count(ports), 3000);
}
END_TEST

START_TEST(test_overlapping_ranges_4)
{
  nc_ports_t ports = NULL;
  netcat_ports_insert(&ports, 1000, 1999);
  netcat_ports_insert(&ports, 3000, 3999);
  netcat_ports_insert(&ports, 1500, 3499);
  ck_assert_int_eq(ports->start, 1000);
  ck_assert_int_eq(ports->end, 4000);
  ck_assert(!ports->next);
  ck_assert_int_eq(netcat_ports_count(ports), 3000);
}
END_TEST

START_TEST(test_overlapping_ranges_5)
{
  nc_ports_t ports = NULL;
  netcat_ports_insert(&ports, 1300, 1399);
  netcat_ports_insert(&ports, 1600, 1699);
  netcat_ports_insert(&ports, 1000, 1999);
  ck_assert_int_eq(ports->start, 1000);
  ck_assert_int_eq(ports->end, 2000);
  ck_assert(!ports->next);
  ck_assert_int_eq(netcat_ports_count(ports), 1000);
}
END_TEST

START_TEST(test_ports_next)
{
  nc_ports_t ports = NULL;
  netcat_ports_insert(&ports, 10, 11);
  netcat_ports_insert(&ports, 15, 16);
  netcat_ports_insert(&ports, 18, 19);
  ck_assert_int_eq(netcat_ports_next(ports, 0), 10);
  ck_assert_int_eq(netcat_ports_next(ports, 10), 11);
  ck_assert_int_eq(netcat_ports_next(ports, 11), 15);
  ck_assert_int_eq(netcat_ports_next(ports, 15), 16);
  ck_assert_int_eq(netcat_ports_next(ports, 16), 18);
  ck_assert_int_eq(netcat_ports_next(ports, 18), 19);
  ck_assert_int_eq(netcat_ports_next(ports, 19), 0);
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
  tcase_add_test(tc_core, test_adjacent_ranges);
  tcase_add_test(tc_core, test_overlapping_ranges_1);
  tcase_add_test(tc_core, test_overlapping_ranges_2);
  tcase_add_test(tc_core, test_overlapping_ranges_3);
  tcase_add_test(tc_core, test_overlapping_ranges_4);
  tcase_add_test(tc_core, test_overlapping_ranges_5);
  tcase_add_test(tc_core, test_ports_next);
  suite_add_tcase(s, tc_core);
  SRunner *sr = srunner_create(s);
  srunner_run_all(sr, CK_NORMAL);
  number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
