#ifndef _FRONTEND_H
#define _FRONTEND_H

#include "kernel_list.h"
#include "hash_table.h"
#include "notify.h"

#define FRONTEND_SOCKET_MAX_NUM         5000
#define FRONTEND_THREAD_HASH_SIZE       (FRONTEND_SOCKET_MAX_NUM / FRONTEND_WORK_THREAD_NUM)

#define FRONTEND_ACCEPT_EPOLL_MAX_EVENTS     5000
#define FRONTEND_ACCEPT_LISTEN_BACKLOG       500

#define FRONTEND_THREAD_EPOLL_MAX_EVENTS  (FRONTEND_ACCEPT_EPOLL_MAX_EVENTS / FRONTEND_WORK_THREAD_NUM)
#define FRONTEND_THREAD_LISTEN_BACKLOG  (FRONTEND_ACCEPT_LISTEN_BACKLOG / FRONTEND_WORK_THREAD_NUM)

enum http_state{
    HTTP_STATE_INIT,
    HTTP_STATE_REQUEST,
    HTTP_STATE_RELAY,
};

struct http_parse_block {
    int                     start;
    int                     end;
    int                     pos;
    
    ngx_str_t               request_line;
    ngx_str_t               user_agent;
    ngx_str_t               host;
    
    unsigned int            connect_method;
    uint64_t                content_length;

    uint8_t                 headers_finish;
    uint8_t                 content_finish;
    
    struct request_s        request;
};


struct frontend_sk_node {
    struct list_head            list_head;
    struct list_head            id_hash_node;

    int                         fd;
    uint32_t                    seq_id;

    uint32_t                    ip;
    uint16_t                    port;

    uint32_t                    user_block_id;
    uint32_t                    front_listen_id;

    void                        *p_my_table;

    struct notify_node          *p_recv_node;
    struct list_head            send_list;

    time_t                      last_active;

    uint8_t                     status;

    uint8_t                     type;
    uint8_t                     blocked;

    enum http_state             state;
    struct http_parse_block     parse_block;

    void                        (*read_cb)(void *v);
    void                        (*write_cb)(void *v);
    void                        (*exit_cb)(void *v);
    void                        (*del_cb)(void *v);
};

enum {
    FRONTEND_SOCKET_TYPE_READY,
    FRONTEND_SOCKET_TYPE_DEL,
    FRONTEND_SOCKET_TYPE_MAX
};

struct frontend_work_thread_table {
    int                     index;
    pthread_t               thread_id;
    char                    table_name[TABLE_NAME_LEN + 1];
    pthread_mutex_t         mutex;

    struct list_table       list_head[FRONTEND_SOCKET_TYPE_MAX];

    struct hash_table       hash;
    struct notify_table     notify;

    int                     event_fd;
    int                     epfd;
    struct epoll_event      *events;
};

int frontend_init();
void *frontend_accept_process(void *arg);

int frontend_notify_send_data(struct notify_node *p_notify_node, uint32_t src_id, uint32_t dst_id);
#endif
