#ifndef _MAIN_H
#define _MAIN_H

#include "misc.h"
#include "kernel_list.h"

#define USER_NUM      100

#define FRONTEND_HTTP_PORT   80
#define FRONTEND_HTTPS_PORT   443
#define FRONTEND_WORK_THREAD_NUM    4

#define BACKEND_PORT   66
#define BACKEND_WORK_THREAD_NUM    4

#define USER_PORT     (800)

#define TABLE_NAME_LEN     50
#define USER_NAME_MAX_LEN  64
#define PASSWORD_MAX_LEN   64
#define DOMAIN_MAX_LEN     64
#define MD5_MAX_LEN        32

#define MAX_BUFF_SIZE            2048

#define SUCCESS    0
#define FAIL       -1
#define NEED_MORE  -2

enum socket_status {
    SOCKET_STATUS_NEW = 0,
    SOCKET_STATUS_EXIT_AFTER_SEND,
    SOCKET_STATUS_UNUSE_AFTER_SEND,
    SOCKET_STATUS_DEL,
    SOCKET_STATUS_MAX
};

struct list_table {
    struct list_head    list_head;
    uint32_t            num;
};


struct accept_socket_table {
    int                     fd;
    int                     event_fd;
    int                     epfd;
    struct epoll_event      *events;
};

extern int g_main_running;
#endif
