#ifndef _BUFF_H
#define _BUFF_H

#include <stdint.h>

#include "kernel_list.h"

#define BUFF_MALLOC_MAX_TIMES       100
#define BUFF_TABLE_NAME_LEN   100

struct buff_table {
    struct list_head    list_head;
    uint32_t            num;

    char                table_name[BUFF_TABLE_NAME_LEN + 1];
    uint32_t            limit_size;

    uint32_t            node_size;
    uint32_t            malloc_count;
    uint32_t            total_count;

    pthread_mutex_t     mutex;
};

int buff_table_init(struct buff_table *p_table, uint32_t limit_size, uint32_t node_size, const char* name);
struct list_head *buff_table_malloc_node(struct buff_table *p_table);
void buff_table_free_node(struct buff_table *p_table, struct list_head *p_node);
void display_buff_table(struct buff_table *p_buff_table);

#endif
