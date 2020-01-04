#ifndef _HEAPTIMER_H_
#define _HEAPTIMER_H_
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#include "main.h"


struct heap_timer {
    uint32_t            hole;
    uint32_t            timeout;
};

struct heap_tree {
    struct heap_timer   **array;
    int                 size;
    int                 cur_size;
    //pthread_mutex_t     mutex;
};

int init_heap_timer(struct heap_tree *p_heap_tree, int size);
int add_heap_timer(struct heap_tree *p_heap_tree, struct heap_timer *p_new_timer);
struct heap_timer *top_heap_timer(struct heap_tree *p_heap_tree);
struct heap_timer *pop_heap_timer(struct heap_tree *p_heap_tree);
struct heap_timer *del_heap_timer(struct heap_tree *p_heap_tree, uint32_t hole);
void test_heap_timer();

#endif
