#ifndef _BUFF_LIST_H
#define _BUFF_LIST_H

#include <stdint.h>

#include "kernel_list.h"

#define FREE_NODE_BUFF_TABLE_NAME_LEN   100    
struct free_node_buff_table{
    struct list_head    list_head;
    uint32_t            num;
    
    char                table_name[FREE_NODE_BUFF_TABLE_NAME_LEN + 1];
    uint32_t            limit_size;
    
    uint32_t            node_size;
    uint32_t            malloc_count;
    uint32_t            total_count;
    
    pthread_mutex_t     mutex;
};

int free_node_buff_table_init(struct free_node_buff_table *p_table, uint32_t limit_size, uint32_t node_size, uint32_t malloc_count, const char* name);
struct list_head *free_node_buff_table_malloc_node(struct free_node_buff_table *p_table);
void free_node_buff_table_free_node(struct free_node_buff_table *p_table, struct list_head *p_node);
void display_buff_table(struct free_node_buff_table *p_buff_table);

#endif
