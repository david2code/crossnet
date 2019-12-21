#include <stdio.h>  
#include <stdlib.h>
#include <string.h>
#include "buff_list.h"
#include "misc_func.h"
#include "log.h"

int free_node_buff_table_init(struct free_node_buff_table *p_table, uint32_t limit_size, uint32_t node_size, uint32_t malloc_count, const char* name)
{
    INIT_LIST_HEAD(&p_table->list_head);
    p_table->num = 0;
    pthread_mutex_init(&p_table->mutex, NULL);
    strncpy(p_table->table_name, name, free_node_buff_table_NAME_LEN);
    p_table->limit_size    = limit_size;
    p_table->node_size     = node_size;
    p_table->malloc_count  = malloc_count;
    p_table->total_count   = 0;

    DBG_PRINTF(DEBUG_WARNING, "init buff_table: %-30s, limit_size: %8d, node_size: %6d, malloc_count: %3d\n",
            p_table->table_name,
            p_table->limit_size,
            p_table->node_size,
            p_table->malloc_count
            );
    return 0;
}

struct list_head *free_node_buff_table_malloc_entry(struct free_node_buff_table *p_table)
{
    if (p_table->total_count >= p_table->limit_size) {
        DBG_PRINTF(DEBUG_WARNING, "%s full, total_count: %u, limit_size: %u!\n",
            p_table->table_name,
            p_table->total_count,
            p_table->limit_size);
        return NULL;
    }
    
    struct list_head *p_entry = (struct list_head *)malloc(p_table->node_size * p_table->malloc_count);

    if (NULL == p_entry)
        return p_entry;

    p_table->total_count += p_table->malloc_count;
    p_table->num += (p_table->malloc_count - 1);
    int i = 0;
    struct list_head *p_node = p_entry;
    for (i = 1; i < p_table->malloc_count; i++) {
        p_node = (struct list_head *)((char *)p_node + p_table->node_size);
        list_add_fe(p_node, &p_table->list_head);
    }

    return p_entry;
}

struct list_head *free_node_buff_table_malloc_node(struct free_node_buff_table *p_table)
{
    struct list_head *p_node = NULL;
    
    pthread_mutex_lock(&p_table->mutex);

    if (list_empty(&p_table->list_head)) {
        p_node = lt_free_node_buff_table_malloc_entry(p_table);
    } else {
        p_node = p_table->list_head.next;
        
        list_del(p_node);
        p_table->num--;
    }
    pthread_mutex_unlock(&p_table->mutex);
    return p_node;
}

void free_node_buff_table_free_node(struct free_node_buff_table *p_table, struct list_head *p_node)
{
    pthread_mutex_lock(&p_table->mutex);

    if (p_table->malloc_count == 1
        && (p_table->num * 100 / p_table->total_count) > 20) {
        free(p_node);
        p_table->total_count--;
    } else {
        list_add_tail(p_node, &p_table->list_head);
        p_table->num++;
    }
    
    pthread_mutex_unlock(&p_table->mutex);
}


void display_buff_table(struct free_node_buff_table *p_buff_table)
{
    DBG_RAW_PRINTF("\n");
    pthread_mutex_lock(&p_buff_table->mutex);
    
    DBG_PRINTF(DEBUG_WARNING, "table_name: %s, limit_size: %u, node_size: %u, malloc_count: %u, total_count: %u, avaiable num: %u\n", 
        p_buff_table->table_name,
        p_buff_table->limit_size,
        p_buff_table->node_size,
        p_buff_table->malloc_count,
        p_buff_table->total_count,
        p_buff_table->num);
    
    pthread_mutex_unlock(&p_buff_table->mutex);
    DBG_RAW_PRINTF("\n");
}

