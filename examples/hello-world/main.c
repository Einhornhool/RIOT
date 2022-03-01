/*
 * Copyright (C) 2014 Freie Universität Berlin
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     examples
 * @{
 *
 * @file
 * @brief       Hello World application
 *
 * @author      Kaspar Schleiser <kaspar@schleiser.de>
 * @author      Ludwig Knüpfer <ludwig.knuepfer@fu-berlin.de>
 *
 * @}
 */

#include <stdio.h>
#include <stddef.h>
#include "kernel_defines.h"
#include "clist.h"

typedef struct {
    int one;
    int two;
    clist_node_t whut;
} test_t;

static test_t clist_buf[8];
static list_node_t test_list;
static list_node_t empty_list;

int is_node(clist_node_t * n, void *arg) {
    test_t * me = container_of(n, test_t, whut);
    int * comp = (int *) arg;
    if (me->two == *comp) {
        return 1;
    }
    return 0;
}

int main(void)
{
    puts("Start\n");

    for (size_t i = 0; i < 8; i++) {
        clist_rpush(&empty_list, &clist_buf[i].whut);
    }
    printf("Empty List: Elements: %d\n", clist_count(&empty_list));
    printf("List: Elements: %d\n", clist_count(&test_list));

    clist_node_t * list = &test_list;

    clist_node_t * new = clist_rpop(&empty_list);
    clist_rpush(list, new);
    printf("Empty List: Elements: %d\n", clist_count(&empty_list));
    printf("List: Elements: %d\n", clist_count(list));

    test_t * item = container_of(list->next, test_t, whut);

    item->one = 1;
    item->two = 2;

    clist_node_t * new_1 = clist_rpop(&empty_list);
    clist_rpush(list, new_1);
    new = clist_rpop(&empty_list);
    clist_rpush(list, new);
    printf("Empty List: Elements: %d\n", clist_count(&empty_list));
    printf("List: Elements: %d\n", clist_count(list));

    test_t * quark = container_of(new, test_t, whut);
    quark->one = 67;
    quark->two = 1312;

    test_t * dings = container_of(new_1, test_t, whut);
    printf("dings One: %d, Two: %d\n", dings->one, dings->two);

    clist_node_t * find = clist_foreach(list, is_node, &item->two);
    test_t * find_a = container_of(find, test_t, whut);
    printf("find One: %d, Two: %d\n", find_a->one, find_a->two);

    int a = 1312;
    find = clist_foreach(list, is_node, &a);
    if (find == NULL) {
        puts("Null");
    }
    else {
        find_a = container_of(find, test_t, whut);
        printf("find One: %d, Two: %d\n", find_a->one, find_a->two);
    }
    return 0;
}