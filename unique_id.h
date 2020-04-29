#ifndef __SESSION_ID_H
#define __SESSION_ID_H

#include "limits.h"
#include "kernel_list.h"

enum{
    SESSION_ID_CLIENT_START = 0,
    SESSION_ID_CLIENT_END = 1000,
    SESSION_ID_SERVER_START,
    SESSION_ID_SERVER_END = UINT_MAX,
};

#define SESSION_ID_REUSE_SIZE    (60000)

struct unique_id_node {
    struct list_head    list_head;

    uint32_t            id;
};

struct unique_id_table {
    struct list_head    inuse;
    struct list_head    unuse;
    uint32_t            inuse_num;

    uint32_t            id;

    pthread_mutex_t     mutex;
};

int unique_id_init();
uint32_t unique_id_get();
void unique_id_put(uint32_t id);

void display_g_unique_id_table();
void display_g_unique_id_buff_table();



#endif

