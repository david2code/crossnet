#ifndef _USER_H
#define _USER_H

#include "main.h"
#include "hash_table.h"

#define USER_SOCKET_TIMEOUT_MAX_SECONDS       (20)
#define USER_SOCKET_CHECK_PERIOD_SECONDS      (USER_SOCKET_TIMEOUT_MAX_SECONDS * 5)

#define USER_IP_OLD_CHECK_PERIOD_SECONDS       (2 * 60)

#define USER_MAX_NUM                   (2000)

#define USER_EPOLL_ACCEPT_MAX_EVENTS          (USER_MAX_NUM)
#define USER_SOCKET_LISTEN_BACKLOG            (USER_EPOLL_ACCEPT_MAX_EVENTS)
#define USER_SOCKET_BUF_MAX_NUM               (USER_MAX_NUM * 2)

#define TIME_INVALID_VALUE      (0)
#define UINT64_INVALID_VALUE      (UINT64_MAX)

enum user_fmt_type {
    USER_FMT_TYPE_DEFAULT       = 0,
    USER_FMT_TYPE_MAX
};

enum user_code_type {
    USER_CODE_TYPE_SUCCESS          = 0,
    USER_CODE_TYPE_URL_ERR          = 1,
    USER_CODE_TYPE_AUTH_FAIL        = 2,
    USER_CODE_TYPE_EXPIRE           = 3,
    USER_CODE_TYPE_QUOTA_USEOUT     = 4,
    USER_CODE_TYPE_PARAM_ERR        = 5,
    USER_CODE_TYPE_USER_EXIST       = 6,
    USER_CODE_TYPE_USER_NOT_FOUND   = 7,
    USER_CODE_TYPE_USER_ALREADY_DEL = 8,
    USER_CODE_TYPE_INNER_ERR        = 9,
    USER_CODE_TYPE_MAX
};

enum user_req_type {
    USER_REQ_TYPE_NEED_MORE, /* need more data to parse */
    USER_REQ_TYPE_UNKNOWN,
    USER_REQ_TYPE_DEBUG,
    USER_REQ_TYPE_ADD_ACCOUNT,
    USER_REQ_TYPE_MDF_ACCOUNT,
    USER_REQ_TYPE_DEL_ACCOUNT,
    USER_REQ_TYPE_QUERY_ACCOUNT,
    USER_REQ_TYPE_QUERY_IP,
    USER_REQ_TYPE_MAX
};

struct user_debug_block {
    ngx_str_t               pattern;

    ngx_str_t               param[5]; /*第一个参数是func_name,后面的就是参数*/
    int                     param_num;

};

struct user_account_block {
    ngx_str_t               pattern;
    ngx_str_t               ngx_user_name;
    ngx_str_t               ngx_password;
    ngx_str_t               ngx_domain;
    ngx_str_t               prefix;
    time_t                  end_time;
    uint64_t                total_flow;
    uint64_t                used_flow;

    char                    user_name[USER_NAME_MAX_LEN + 1];
    char                    password[PASSWORD_MAX_LEN + 1];
    char                    domain[DOMAIN_MAX_LEN + 1];
};

struct user_query_ip_block {
    ngx_str_t               pattern;
    ngx_str_t               user_name;
    uint32_t                ip;
};

struct user_interface_parse_block{
    enum user_req_type      type;
    enum user_code_type     code;

    union {
        ngx_str_t                               pattern;
        struct user_debug_block                 debug;
        struct user_account_block               account;
        struct user_query_ip_block              query;
    }req;

    union {
        struct user_account_block               account;
    }resp;
};

#define USER_MAX_RESP_BUF_SIZE            (200 * 1024)

struct user_resp_buf_node {
    struct list_head        list_head;

    uint32_t                pos;
    uint32_t                end;
    uint8_t                 buf[USER_MAX_RESP_BUF_SIZE];
};

struct user_sk_node {
    struct list_head    list_head;

    int                 fd;
    uint32_t            seq_id;

    uint32_t            ip;
    uint16_t            port;

    void                *p_table;

    struct user_resp_buf_node *p_recv_node;/*存储接收数据*/
    struct list_head    send_list;/*存储发送数据节点*/

    time_t              last_active;
    time_t              start_time;

    uint8_t             status;         /* 当前状态 */

    uint8_t             type;           /* 当前socket的类型，从而确定其所在的list */
    uint8_t             blocked;

    void                (*read_cb)(void *v);
    void                (*write_cb)(void *v);
    void                (*exit_cb)(void *v);/* 此回调函数将当前socket从epoll监听中删除 */
    void                (*del_cb)(void *v);
};

enum {
    USER_SOCKET_TYPE_WORKER,
    USER_SOCKET_TYPE_DEL,
    USER_SOCKET_TYPE_MAX
};

struct user_socket_table {
    int                     index;
    pthread_t               thread_id;
    pthread_mutex_t         mutex;
    char                    table_name[TABLE_NAME_LEN + 1];

    struct list_table       list_head[USER_SOCKET_TYPE_MAX];

    int                     epfd;
    struct epoll_event      *events;
};


struct user_node {
    struct list_head            list_head;
    struct list_head            hash_node;

    uint32_t                    user_id;
    char                        user_name[USER_NAME_MAX_LEN + 1];
    ngx_str_t                   ngx_user_name;

    char                        password[PASSWORD_MAX_LEN + 1];
    ngx_str_t                   ngx_password;

    char                        domain[DOMAIN_MAX_LEN + 1];
    ngx_str_t                   ngx_domain;

    time_t                      start_time;
    time_t                      end_time;
    uint8_t                     del_flag;
    uint64_t                    total_flow;
    uint64_t                    used_flow;

    time_t                      time;

    bool                        store;
};

struct user_table {
    pthread_mutex_t         mutex;
    char                    table_name[TABLE_NAME_LEN + 1];

    uint32_t                current_max_user_id;
    struct list_table       list;
    struct hash_table       hash;
};

void user_socket_init();
void user_table_init();
inline void user_table_lock();
inline void user_table_unlock();

int user_add_account_to_table(
        enum user_code_type *code,
        uint32_t user_id,
        char *user_name,
        char *password,
        char *domain,
        time_t start_time,
        time_t end_time,
        uint8_t del_flag,
        uint64_t total_flow,
        uint64_t used_flow,
        time_t time
        );
void *user_socket_process(void *arg);

void display_g_user_table();

void display_g_user_buff_table();
void display_g_user_socket_buff_table();
void display_g_user_resp_buff_table();

#endif
