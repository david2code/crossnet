#ifndef __UNIQUE_ID_H
#define __UNIQUE_ID_H

#include "limits.h"
#include "kernel_list.h"

enum{
    UNIQUE_ID_ROUTER_START = 0,
    UNIQUE_ID_ROUTER_END = 1000,
    UNIQUE_ID_SERVER_START,
    UNIQUE_ID_SERVER_END = UINT_MAX,
};

#define UNIQUE_ID_REUSE_SIZE    (60000)

struct unique_id_info_t{
    struct list_head    list_head;

    uint32_t            id;
};

struct unique_id_info_table{
    struct list_head    inuse;
    struct list_head    unuse;
    uint32_t            inuse_num;

    char                table_name[30];
    uint32_t            id;

    pthread_mutex_t     mutex;
};

void unique_id_info_init();
uint32_t unique_id_get();
void unique_id_put(uint32_t id);
void display_g_unique_id_table();
void display_g_unique_buff_table();



#endif

