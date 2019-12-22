#ifndef _NOTIFY_H
#define _NOTIFY_H

#include "main.h"

#define NOTIFY_NODE_MAX_NUM         (USER_NUM * 2)

struct notify_table {
    struct list_head    list_head;
    uint32_t            list_num;
    
    char                table_name[TABLE_NAME_LEN + 1];
    uint32_t            limit_size;
    pthread_mutex_t     mutex;
};

enum pipe_notify_type {
    PIPE_NOTIFY_TYPE_SOCKET_NODE,
    PIPE_NOTIFY_TYPE_PAIRS_INFO,
    PIPE_NOTIFY_TYPE_SELF_SEND,/* socket通知自己将数据发送出去*/
    PIPE_NOTIFY_TYPE_SEND,/* socket通知对方将数据发送出去*/
    PIPE_NOTIFY_TYPE_FREE,/* socket通知对方释放掉自己，状态由占用变为未占用 */
    PIPE_NOTIFY_TYPE_MAX
};

struct notify_node {
    struct list_head        list_head;
    
    enum pipe_notify_type   type;
    void                    *p_node;
    uint32_t                src_id;
    uint32_t                dst_id;
    uint16_t                pos;
    uint16_t                end;
    uint8_t                 have_debug_id;
    uint8_t                 buf[MAX_BUFF_SIZE];    
};

enum socket_nofity_type {
    SOCKET_NOTIFY_TYPE_FREE,
    SOCKET_NOTIFY_TYPE_FRONT,
    SOCKET_NOTIFY_TYPE_MANAGE,
    SOCKET_NOTIFY_TYPE_USER,
    SOCKET_NOTIFY_TYPE_MAX
};

int lt_nofity_make_cmd_to_manage(uint32_t src_id, uint32_t dest_id, enum pipe_notify_type type);
int lt_nofity_make_cmd_to_front(uint32_t src_id, uint32_t dest_id, enum pipe_notify_type type);
//int lt_nofity_make_cmd_to_user(uint32_t src_id, uint32_t dest_id, struct front_socket_stat *p_stat, enum pipe_notify_type type);
void display_g_notify_buff_table();

void notify_buf_table_init();
struct notify_node *malloc_notify_node();
void free_notify_node(struct notify_node *p_node);

int notify_table_init(struct notify_table *p_table, char *name, uint32_t limit_size);
struct notify_node *notify_table_get(struct notify_table *p_table);
int notify_table_put_head(struct notify_table *p_table, struct notify_node *p_node);
int notify_table_put_tail(struct notify_table *p_table, struct notify_node *p_node);
#endif
