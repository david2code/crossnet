#ifndef _DOMAIN_MAP_H
#define _DOMAIN_MAP_H

#include "main.h"
#include "hash_table.h"

#define DOMAIN_MAP_MAX_NUM                   (2000)
#define DOMAIN_MAP_HASH_SIZE                 (DOMAIN_MAP_MAX_NUM / 2)

struct domain_node {
    struct list_head            list_head;
    struct list_head            hash_node;

    char                        domain[DOMAIN_MAX_LEN + 1];
    ngx_str_t                   ngx_domain;

    uint32_t                    user_id;
    uint32_t                    backend_id;
    uint64_t                    used_flow;

    uint32_t                    ip;
    bool                        stop;/*stop when flow is used out*/

    bool                        del_flag;
};

struct domain_map_table {
    pthread_rwlock_t        rwlock;
    char                    table_name[TABLE_NAME_LEN + 1];

    struct list_table       list;
    struct hash_table       hash;
};

extern void domain_map_rdlock();
extern void domain_map_wrlock();
extern void domain_map_unlock();

void domain_map_table_init();
int domain_map_insert(struct domain_node *p_domain_node);
int domain_map_delete(ngx_str_t *p_ngx_domain, uint32_t backend_id);
int domain_map_query(struct domain_node *p_domain_node, ngx_str_t *p_ngx_domain);
void display_g_domain_buff_table();
void display_g_domain_map_table();

void domain_map_mark();
int domain_map_insert_or_update(struct domain_node *p_domain_node);
void domain_map_del();

#endif
