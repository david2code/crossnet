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

DHASH_GENERATE(g_domain_map_table, user_node, hash_node, ngx_user_name, ngx_str_t, ngx_hash, ngx_cmp);

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


int domain_map_insert()
{
    return 0;
}
#endif
