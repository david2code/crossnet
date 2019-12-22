#ifndef _MAIN_H
#define _MAIN_H

#include "misc.h"
#include "kernel_list.h"

#define USER_NUM      100

#define BACKEND_PORT   66 
#define BACKEND_WORK_THREAD_NUM    4

#define TABLE_NAME_LEN  50
#define MAX_BUFF_SIZE            2048

enum debug_level
{
	DEBUG_CLOSE,  /* 0 */
	DEBUG_ERROR,  /* 1 */
	DEBUG_WARNING,/* 2 */
    DEBUG_NORMAL, /* 3 */
    DEBUG_MAX,
};  

typedef enum{
    SOCKET_STATUS_NEW = 0,
    SOCKET_STATUS_EXIT_AFTER_SEND,/* socket需要被关闭 */
    SOCKET_STATUS_UNUSE_AFTER_SEND,
    SOCKET_STATUS_DEL,/* socket需要被删除 */
    SOCKET_STATUS_MAX
}socket_status_t;

struct list_table{
    struct list_head    list_head;
    uint32_t            num;
};


extern int g_main_running;
#endif
