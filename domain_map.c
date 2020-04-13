#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#include <stddef.h>
#include <limits.h>

#include <sys/msg.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <pthread.h>
#include <sys/prctl.h>
#include <sys/select.h>
#include <netinet/tcp.h>
#include <openssl/md5.h>
#include <json-c/json.h>
#include <sys/eventfd.h>
#include <sys/time.h>

#include "dc_mysql.h"
#include "log.h"
#include "misc.h"
#include "buff.h"
#include "domain_map.h"
#include "user.h"
#include "backend.h"

extern int g_main_running;
extern int g_main_debug;

#if 1

struct buff_table g_domain_buf_table;

void domain_buf_table_init()
{
    buff_table_init(&g_domain_buf_table, USER_MAX_NUM, sizeof(struct domain_node), "g_domain_buf_table");
}

inline struct domain_node *malloc_domain_node()
{
    return (struct domain_node *)buff_table_malloc_node(&g_domain_buf_table);
}

inline void free_domain_node(struct domain_node *p_node)
{
    buff_table_free_node(&g_domain_buf_table, &p_node->list_head);
}

void display_g_domain_buff_table()
{
    display_buff_table(&g_domain_buf_table);
}

#endif

#if 2

struct domain_map_table g_domain_map_table;

DHASH_GENERATE(g_domain_map_table, domain_node, hash_node, ngx_domain, ngx_str_t, ngx_hash, ngx_cmp);

inline void domain_map_rdlock()
{
    pthread_rwlock_rdlock(&g_domain_map_table.rwlock);
}
inline void domain_map_wrlock()
{
    pthread_rwlock_wrlock(&g_domain_map_table.rwlock);
}
inline void domain_map_unlock()
{
    pthread_rwlock_unlock(&g_domain_map_table.rwlock);
}

/*
 * should init before user_table, backend_table
 */
void domain_map_table_init()
{
    domain_buf_table_init();

    struct domain_map_table *p_table = &g_domain_map_table;

    pthread_rwlock_init(&p_table->rwlock, NULL);

    strncpy(p_table->table_name, "g_domain_map_table", TABLE_NAME_LEN);

    INIT_LIST_HEAD(&p_table->list.list_head);
    p_table->list.num = 0;

    DHASH_INIT(g_domain_map_table, &p_table->hash, DOMAIN_MAP_HASH_SIZE);
}


int domain_map_insert(struct domain_node *p_domain_node)
{
    struct domain_map_table *p_table = &g_domain_map_table;
    int ret = SUCCESS;

    domain_map_wrlock();

    struct domain_node *p_entry = DHASH_FIND(g_domain_map_table, &p_table->hash, &p_domain_node->ngx_domain);
    if (p_entry) {
        //TODO force quit
        backend_notify_force_offline(p_entry->backend_id, p_domain_node->ip);

        //domain conflict
        if (p_entry->user_id != p_domain_node->user_id) {
            p_entry->user_id = p_domain_node->user_id;
        }
        p_entry->backend_id = p_domain_node->backend_id;

        goto EXIT;
    }

    p_entry = malloc_domain_node();
    if (p_entry == NULL) {
        ret = FAIL;
        goto EXIT;
    }

    strncpy(p_entry->domain, p_domain_node->domain, DOMAIN_MAX_LEN);
    p_entry->domain[DOMAIN_MAX_LEN] = 0;
    p_entry->ngx_domain.data = (uint8_t *)p_entry->domain;
    p_entry->ngx_domain.len = strlen(p_entry->domain);

    p_entry->user_id = p_domain_node->user_id;
    p_entry->backend_id = p_domain_node->backend_id;

    if (-1 == DHASH_INSERT(g_domain_map_table, &p_table->hash, p_entry)) {
        DBG_PRINTF(DBG_ERROR, "add new domain node[%s], failed add hash failed\n", p_entry->domain);
        free_domain_node(p_entry);
        ret = FAIL;
        goto EXIT;
    }

    list_add_fe(&p_entry->list_head, &p_table->list.list_head);
    p_table->list.num++;

EXIT:
    domain_map_unlock();

    DBG_PRINTF(DBG_WARNING, "domain %s user_id %u backend_id %u, insert success\n",
            p_domain_node->domain,
            p_domain_node->user_id,
            p_domain_node->backend_id);
    return ret;
}

int domain_map_delete(ngx_str_t *p_ngx_domain, uint32_t backend_id)
{
    struct domain_map_table *p_table = &g_domain_map_table;
    int ret = SUCCESS;

    domain_map_wrlock();

    struct domain_node *p_entry = DHASH_FIND(g_domain_map_table, &p_table->hash, p_ngx_domain);
    if (p_entry) {
        if (p_entry->backend_id == backend_id) {
            list_del(&p_entry->hash_node);
            list_del(&p_entry->list_head);
            p_table->list.num--;

            DBG_PRINTF(DBG_WARNING, "domain %s user_id %u backend_id %u, del success\n",
                    p_entry->domain,
                    p_entry->user_id,
                    p_entry->backend_id);

            free_domain_node(p_entry);
        } else {
            DBG_PRINTF(DBG_WARNING, "domain %s backend_id unmatch %u %u, del fail\n",
                    p_entry->domain,
                    p_entry->backend_id,
                    backend_id);

        }
    } else {
        if (g_main_debug > DBG_WARNING) {
            char domain[DOMAIN_MAX_LEN + 1];
            DBG_PRINTF(DBG_WARNING, "domain %s not found\n",
                    ngx_print(domain, DOMAIN_MAX_LEN, p_ngx_domain));
        }
        ret = FAIL;
    }

    domain_map_unlock();

    return ret;
}

int domain_map_query(struct domain_node *p_domain_node, ngx_str_t *p_ngx_domain)
{
    struct domain_map_table *p_table = &g_domain_map_table;
    int ret = SUCCESS;

    domain_map_rdlock();

    struct domain_node *p_entry = DHASH_FIND(g_domain_map_table, &p_table->hash, p_ngx_domain);
    if (p_entry) {
        memcpy(p_domain_node, p_entry, sizeof(struct domain_node));
    } else {
        if (g_main_debug > DBG_WARNING) {
            char domain[DOMAIN_MAX_LEN + 1];
            DBG_PRINTF(DBG_WARNING, "domain %s not found\n",
                    ngx_print(domain, DOMAIN_MAX_LEN, p_ngx_domain));
        }
        ret = FAIL;
    }

    domain_map_unlock();

    return ret;
}

void display_g_domain_map_table()
{
    struct domain_map_table *p_table = &g_domain_map_table;
    struct list_head            *p_list = NULL;
    struct list_table           *p_list_table = &p_table->list;

    domain_map_wrlock();

    DBG_RAW_PRINTF("\n%s, %d, num: %hu, display start\n", __FUNCTION__, __LINE__, p_list_table->num);
    list_for_each(p_list, &p_list_table->list_head) {
        struct domain_node *p_entry = list_entry(p_list, struct domain_node, list_head);

        DBG_RAW_PRINTF(" user_id:%5u,backend_id:%8u,domain:%20s\n",
                p_entry->user_id,
                p_entry->backend_id,
                p_entry->domain
                );
    }

    domain_map_unlock();

    DBG_RAW_PRINTF("\n%s, %d, display end\n", __FUNCTION__, __LINE__);
}

#endif
