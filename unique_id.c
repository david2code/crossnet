#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#include <stddef.h>
#include <limits.h>
#include <pthread.h>

#include "log.h"
#include "misc.h"
#include "buff.h"
#include "unique_id.h"
#include "main.h"

#if 1
struct buff_table g_unique_buf_table;

void unique_buf_table_init()
{
    buff_table_init(&g_unique_buf_table, UNIQUE_ID_REUSE_SIZE, sizeof(struct unique_id_node), "g_unique_buf_table");
}

inline struct unique_id_node *malloc_unique_node()
{
    return (struct unique_id_node *)buff_table_malloc_node(&g_unique_buf_table);
}

inline void free_unique_node(struct unique_id_node *p_node)
{
    buff_table_free_node(&g_unique_buf_table, &p_node->list_head);
}

void display_g_unique_buff_table()
{
    display_buff_table(&g_unique_buf_table);
}

#endif

struct unique_id_table g_unique_id_table;

int unique_id_init()
{
    struct unique_id_table *p_table = &g_unique_id_table;

    unique_buf_table_init();

    INIT_LIST_HEAD(&p_table->inuse);
    INIT_LIST_HEAD(&p_table->unuse);
    p_table->inuse_num = 0;
    pthread_mutex_init(&p_table->mutex, NULL);
    p_table->id = UNIQUE_ID_SERVER_START;

    DBG_PRINTF(DBG_WARNING, "done\n");

    return 0;
}

uint32_t unique_id_get()
{
    struct unique_id_table *p_table = &g_unique_id_table;
    struct unique_id_node *p_node = NULL;
    uint32_t        id = UNIQUE_ID_SERVER_END;

    pthread_mutex_lock(&p_table->mutex);
#if 1
    if (p_table->id < UNIQUE_ID_REUSE_SIZE || list_empty(&p_table->unuse))
    {
        if (p_table->id < UNIQUE_ID_SERVER_END)
        {
            p_node       = malloc_unique_node();
            if (p_node != NULL)
            {
                id   = p_table->id++;
                list_add_fe(&p_node->list_head, &p_table->inuse);
                p_table->inuse_num++;
            }
        }
    }
    else
    {
        struct list_head *p_list = p_table->unuse.next;

        list_move(p_list, &p_table->inuse);
        p_table->inuse_num++;
        p_node = list_entry(p_list, struct unique_id_node, list_head);
        id = p_node->id;
    }
#else
    if (p_table->id < UNIQUE_ID_SERVER_END)
    {
        p_node       = (struct unique_id_node *)malloc(sizeof(struct unique_id_node));
        if (p_node != NULL)
        {
            id   = p_table->id++;
            list_add_fe(&p_node->list_head, &p_table->inuse);
        }
    }
    else if(!list_empty(&p_table->unuse))
    {
        struct list_head *p_list = p_table->unuse.next;

        list_move(p_list, &p_table->inuse);
        p_node = list_entry(p_list, struct unique_id_node, list_head);
        id = p_node->id;
    }
#endif

    pthread_mutex_unlock(&p_table->mutex);
    return id;
}

void unique_id_put(uint32_t id)
{
    struct unique_id_table *p_table = &g_unique_id_table;
    struct unique_id_node *p_node = NULL;
    pthread_mutex_lock(&p_table->mutex);

    if (list_empty(&p_table->inuse)) {
        DBG_PRINTF(DBG_WARNING, "critical error happen, %u!\n", p_table->id);
    } else {
        struct list_head *p_list = p_table->inuse.next;

        list_move_tail(p_list, &p_table->unuse);
        p_table->inuse_num--;
        p_node = list_entry(p_list, struct unique_id_node, list_head);
        p_node->id = id;

    }

    pthread_mutex_unlock(&p_table->mutex);
}

void display_g_unique_id_table()
{
    struct unique_id_table *p_table = &g_unique_id_table;
    DBG_RAW_PRINTF("\n\nid: %d, inuse_num: %u\n\n",
        p_table->id,
        p_table->inuse_num);
}

