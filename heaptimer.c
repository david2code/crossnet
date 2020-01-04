#include <stdio.h>
#include <pthread.h>
#include "heaptimer.h"

int init_heap_timer(struct heap_tree *p_heap_tree, int size)
{
    p_heap_tree->size       = size;
    p_heap_tree->cur_size   = 0;

    p_heap_tree->array = (struct heap_timer **)malloc(sizeof(struct heap_timer *) * p_heap_tree->size);
    if (NULL == p_heap_tree->array)
        return -1;

    int i;
    for (i = 0; i < p_heap_tree->size; i++) {
        p_heap_tree->array[i] = NULL;
    }

    return 0;
}

int add_heap_timer(struct heap_tree *p_heap_tree, struct heap_timer *p_new_timer)
{
    if (NULL == p_new_timer)
        return -1;

    if (p_heap_tree->cur_size >= p_heap_tree->size)
        return -1;

    struct heap_timer **array = p_heap_tree->array;
    int hole = p_heap_tree->cur_size++;
    int parent = 0;
    for ( ; hole > 0; hole = parent) {
        parent = (hole -1) / 2;
        if (array[parent]->timeout <= p_new_timer->timeout)
            break;

        array[hole] = array[parent];
        array[parent]->hole = hole;
    }
    array[hole] = p_new_timer;
    p_new_timer->hole = hole;

    return 0;
}

struct heap_timer *top_heap_timer(struct heap_tree *p_heap_tree)
{
    if (p_heap_tree->cur_size == 0)
        return NULL;
    return p_heap_tree->array[0];
}

void percolate_heap_timer(struct heap_tree *p_heap_tree, int hole)
{
    struct heap_timer **array = p_heap_tree->array;
    struct heap_timer *temp = array[hole];
    int child = 0;

    for (; (hole * 2 + 1) <= (p_heap_tree->cur_size - 1); hole = child) {
        child = hole * 2 + 1;
        if ((child < (p_heap_tree->cur_size - 1))
                && (array[child + 1]->timeout < array[child]->timeout))
            ++child;

        if (array[child]->timeout < temp->timeout) {
            array[hole] = array[child];
            array[child]->hole = hole;
        } else
            break;
    }
    array[hole] = temp;
    temp->hole = hole;
}

struct heap_timer *pop_heap_timer(struct heap_tree *p_heap_tree)
{
    struct heap_timer **array = p_heap_tree->array;
    struct heap_timer *p_top = NULL;

    if (p_heap_tree->cur_size == 0)
        return p_top;

    if (array[0]) {
        p_top = array[0];
        --p_heap_tree->cur_size;
        array[0] = array[p_heap_tree->cur_size];
        array[p_heap_tree->cur_size]->hole = 0;
        percolate_heap_timer(p_heap_tree, 0);
    }
    return p_top;
}

struct heap_timer *del_heap_timer(struct heap_tree *p_heap_tree, uint32_t hole)
{
    struct heap_timer **array = p_heap_tree->array;
    struct heap_timer *p_top = NULL;

    if (p_heap_tree->cur_size == 0
            || hole > p_heap_tree->cur_size)
        return p_top;

    if (array[hole]) {
        p_top = array[hole];
        --p_heap_tree->cur_size;
        array[hole] = array[p_heap_tree->cur_size];
        array[p_heap_tree->cur_size]->hole = hole;
        percolate_heap_timer(p_heap_tree, hole);
    }
    return p_top;
}

void test_heap_timer()
{
    struct heap_tree test_heap_tree;

    init_heap_timer(&test_heap_tree, 500);

    srand(time(NULL));

    int i;
    int add = 0;
    int pop = 0;
    int pop_err = 0;
    int error = 0;
    int value = 1;
    struct heap_timer *p_array[20];
    int num = 0;
    for (i = 0; i < 10; i++) {
        int a = rand();
        //printf("%d\n", a);

        struct heap_timer *p_timer = NULL;
        if (a % 5 < 30) {
            p_timer = (struct heap_timer *)malloc(sizeof(struct heap_timer));
            //p_timer->timeout = a % 100000;
            value = a % 10000;
            p_timer->timeout = value;
            p_array[num++] = p_timer;
            if (-1 == add_heap_timer(&test_heap_tree, p_timer)) {
                error++;
            } else {
                add++;
                printf("add %d, hole %d\n", p_timer->timeout, p_timer->hole);
            }
        } else {
            p_timer = pop_heap_timer(&test_heap_tree);
            if (p_timer) {
                pop++;
                printf("pop %d\n", p_timer->timeout);
                free(p_timer);
            } else {
                pop_err++;
            }
        }
    }

    printf("show--------------------\n\n\n\n");
    for (i = 0; i < num; i++) {
        printf("%d, hole %d\n", p_array[i]->timeout, p_array[i]->hole);
    }
    printf("show--------------------\n\n\n\n");
    for (i = 0; i < num; i++) {
        struct heap_timer *p_timer = NULL;
        p_timer = del_heap_timer(&test_heap_tree, p_array[i]->hole);
        if (p_timer != p_array[i]) 
            printf("error %d, hole %d\n", p_array[i]->timeout, p_array[i]->hole);

    }
    printf("show--------------------\n\n\n\n");
    struct heap_timer *p_timer = NULL;
    int left = 0;
    while (NULL != (p_timer = pop_heap_timer(&test_heap_tree))) {
        left++;
        printf("add %d, hole %d\n", p_timer->timeout, p_timer->hole);
    }
    printf("show--------------------\n\n\n\n");

    printf("add %d, pop %d left %d error %d pop_err %d\n\n",
            add,
            pop,
            left,
            error,
            pop_err);
}

