#ifndef _BACKEND_H
#define _BACKEND_H

#include "kernel_list.h"
#include "hash_table.h"
#include "notify.h"

#define BACKEND_SOCKET_MAX_NUM         5000
#define BACKEND_THREAD_HASH_SIZE       (BACKEND_SOCKET_MAX_NUM / BACKEND_WORK_THREAD_NUM)

#define BACKEND_ACCEPT_EPOLL_MAX_EVENTS     5000
#define BACKEND_ACCEPT_LISTEN_BACKLOG       500

#define BACKEND_THREAD_EPOLL_MAX_EVENTS  (BACKEND_ACCEPT_EPOLL_MAX_EVENTS / BACKEND_WORK_THREAD_NUM)
#define BACKEND_THREAD_LISTEN_BACKLOG  (BACKEND_ACCEPT_LISTEN_BACKLOG / BACKEND_WORK_THREAD_NUM)

struct backend_sk_node {
    struct list_head    list_head;
    struct list_head    mac_hash_node;
    struct list_head    id_hash_node;

    int                 fd;  /* 当前socket的描述符 */
    uint32_t            seq_id;/* 每一个socket都会分配一个seq_id通过这个seq_id找到相应的socket */

    uint32_t            ip;  /*如果accept得到，则为对方的ip，否则是当前监听的ip。下面的port类似*/
    uint16_t            port;

    uint32_t            user_block_id;
    uint32_t            front_listen_id;

    void                *p_my_table;

    struct socket_notify_block *p_recv_node;/*存储接收数据*/
    struct list_head    send_list;/*存储发送数据节点*/

    time_t              last_active;

    uint8_t             status;         /* 当前状态 */
    //enum manage_table_type table_type;

    uint8_t             type;           /* 当前socket的类型，从而确定其所在的list */
    uint8_t             blocked;

    uint32_t            alive_cnt;
    uint32_t            quality;
    uint32_t            delay_ms;

    void                (*read_cb)(void *v);
    void                (*deal_read_data_cb)(void *v);
    void                (*write_cb)(void *v);
    void                (*exit_cb)(void *v);/* 此回调函数将当前socket从epoll监听中删除 */
    void                (*del_cb)(void *v);
};

struct accept_socket_table {
    int                     fd;
    int                     event_fd;
    int                     epfd;
    struct epoll_event      *events;
};

enum {
    BACKEND_SOCKET_TYPE_READY,
    BACKEND_SOCKET_TYPE_DEL,
    BACKEND_SOCKET_TYPE_MAX
};

struct backend_work_thread_table {
    int                     index;
    pthread_t               thread_id;
    char                    table_name[TABLE_NAME_LEN + 1];
    pthread_mutex_t         mutex;    
    
    struct list_table       list_head[BACKEND_SOCKET_TYPE_MAX];
    
    struct hash_table       hash;
    struct notify_table     notify;
    
    int                     event_fd;    
    int                     epfd;
    struct epoll_event      *events;
};

int backend_init();
void *backend_accept_process(void *arg);

#endif
