#ifndef _MAIN_H
#define _MAIN_H

#include "misc.h"
#include "kernel_list.h"

#define USER_NUM      100

#define FRONTEND_PORT   80
//#define FRONTEND_PORT   443
#define FRONTEND_WORK_THREAD_NUM    4

#define BACKEND_PORT   66
#define BACKEND_WORK_THREAD_NUM    4

#define TABLE_NAME_LEN  50
#define MAX_BUFF_SIZE            2048

enum socket_status {
    SOCKET_STATUS_NEW = 0,
    SOCKET_STATUS_EXIT_AFTER_SEND,/* socket需要被关闭 */
    SOCKET_STATUS_UNUSE_AFTER_SEND,
    SOCKET_STATUS_DEL,/* socket需要被删除 */
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
