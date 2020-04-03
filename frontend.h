#ifndef _FRONTEND_H
#define _FRONTEND_H

#include "kernel_list.h"
#include "hash_table.h"
#include "notify.h"

#define FRONTEND_SOCKET_MAX_NUM         5000
#define FRONTEND_THREAD_HASH_SIZE       (FRONTEND_SOCKET_MAX_NUM / FRONTEND_WORK_THREAD_NUM)

#define FRONTEND_LISTEN_SOCKET_MAX_NUM  65535

#define FRONTEND_ACCEPT_EPOLL_MAX_EVENTS     5000
#define FRONTEND_ACCEPT_LISTEN_BACKLOG       500

#define FRONTEND_THREAD_EPOLL_MAX_EVENTS  (FRONTEND_ACCEPT_EPOLL_MAX_EVENTS / FRONTEND_WORK_THREAD_NUM)
#define FRONTEND_THREAD_LISTEN_BACKLOG  (FRONTEND_ACCEPT_LISTEN_BACKLOG / FRONTEND_WORK_THREAD_NUM)

enum http_state{
    HTTP_STATE_INIT,
    HTTP_STATE_REQUEST,
    HTTP_STATE_HELLO,
    HTTP_STATE_RELAY,
};

#define bit_request         ( 1 << 0)
#define bit_host            ( 1 << 1)
#define bit_user_agent      ( 1 << 2)

#define bit_done            (bit_request | bit_host)

#if 1
//tls defines

enum tls_content_type {
    TLS_CONTENT_TYPE_HANDSHAKE = 22,
};

enum handshake_type {
    HANDSHAKE_TYPE_CLIENT_HELLO = 1,
};

enum extension_type {
    EXTENSION_TYPE_SERVER_NAME = 0,
};

struct tls_hdr {
    uint8_t                 content_type;
    uint16_t                version;
    uint16_t                length;
}__attribute__((packed));

struct handshake_hdr {
    uint32_t                type:8;
    uint32_t                length:24;
    uint16_t                version;
    uint8_t                 random[32];
}__attribute__((packed));

struct tlv_hdr {
    uint16_t       type;
    uint16_t       length;
    uint8_t        value[0];
}__attribute__((packed));

#endif

enum con_err_type {
    CON_ERR_TYPE_NONE,
    CON_ERR_TYPE_INNER,
    CON_ERR_TYPE_CLIENT_OFFLINE,
    CON_ERR_TYPE_MAX
};

struct http_parse_block {
    int                     start;
    int                     pos;
    
    ngx_str_t               request_line;
    ngx_str_t               host;
    ngx_str_t               user_agent;

    uint32_t                done_map;
};


struct frontend_sk_node {
    struct list_head            list_head;
    struct list_head            id_hash_node;

    int                         fd;
    uint32_t                    seq_id;
    uint32_t                    backend_id;

    uint32_t                    ip;
    uint16_t                    port;

    uint16_t                    my_port;

    uint32_t                    user_id;
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
    enum con_err_type           err_type;

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

    struct list_table       list[FRONTEND_SOCKET_TYPE_MAX];

    struct hash_table       hash;
    struct notify_table     notify;

    int                     event_fd;
    int                     epfd;
    struct epoll_event      *events;
};


struct frontend_listen_sk_node {
    struct list_head            list_head;
    struct list_head            hash_node;

    int                         fd;
    uint32_t                    backend_id;

    uint16_t                    my_port;

    uint32_t                    user_id;
    uint32_t                    front_listen_id;

    time_t                      last_active;

    uint8_t                     status;

    uint8_t                     type;

    void                        (*accept_cb)(void *v);
    void                        (*exit_cb)(void *v);
};

struct frontend_accept_socket_table {
    struct list_table       list;
    struct hash_table       hash;

    int                     event_fd;
    int                     epfd;
    struct epoll_event      *events;
};

int frontend_init();
void *frontend_accept_process(void *arg);

int frontend_notify_send_data(struct notify_node *p_notify_node, uint32_t src_id, uint32_t dst_id);
#endif
