#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#include <stddef.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <pthread.h>
#include <sys/prctl.h>
#include <sys/epoll.h>

#include "main.h"
#include "log.h"
#include "backend.h"
#include "buff.h"
#include "unique_id.h"
#include "misc.h"


struct accept_socket_table g_backend_accept_socket_table;

#if 1

struct free_node_buff_table g_backend_socket_buff_table;

void backend_socket_buff_table_init()
{
    free_node_buff_table_init(&g_backend_socket_buff_table, BACKEND_SOCKET_BUFF_MAX_NUM, sizeof(struct backend_sk_node), 1000, "g_backend_socket_buff_table");
}

struct backend_sk_node *malloc_backend_socket_node()
{
    struct backend_sk_node *p_node = (struct backend_sk_node *)free_node_buff_table_malloc_node(&g_backend_socket_buff_table);
    if (p_node)
        p_node->seq_id = unique_id_get();
    return p_node;
}

void free_backend_socket_node(struct backend_sk_node *p_node)
{
    unique_id_put(p_node->seq_id);
    free_node_buff_table_free_node(&g_backend_socket_buff_table, &p_node->list_head);
}

void display_g_backend_buff_table()
{
    display_buff_table(&g_backend_socket_buff_table);
}

#endif

int backend_accept_init()
{
    struct accept_socket_table *p_table = (struct accept_socket_table*)&g_backend_accept_socket_table;

    p_table->events = (struct epoll_event *)malloc(sizeof(struct epoll_event) * BACKEND_EPOLL_ACCEPT_MAX_EVENTS);
    if (p_table->events == NULL) {
	    exit(EXIT_FAILURE);
    }
    p_table->epfd = epoll_create(BACKEND_EPOLL_ACCEPT_MAX_EVENTS);

    uint16_t    listen_port = BACKEND_PORT;
    /* 监听在某端口上，处理路由器过来的代理上报数据 */
    int server_socket_fd = create_listen_socket(listen_port, BACKEND_SOCKET_LISTEN_BACKLOG);
    if (server_socket_fd < 0) {
        DBG_PRINTF(DEBUG_ERROR, "create listen socket failed at :%d, errnum: %d\n",
            listen_port,
            server_socket_fd);
	    exit(EXIT_FAILURE);
    } else {
        DBG_PRINTF(DEBUG_WARNING, "create listen socket success at :%d, server_socket_fd: %d\n",
            listen_port,
            server_socket_fd);
    }

    p_table->fd              = server_socket_fd;

    set_none_block(p_table->fd);
    add_event(p_table->epfd, p_table->fd, NULL, EPOLLIN);

    return 0;
}
void backend_init()
{
    backend_socket_buff_table_init();

}

void *backend_accept_process(void *arg)
{
    struct accept_socket_table *p_table = &g_backend_accept_socket_table;

    prctl(PR_SET_NAME, __FUNCTION__);

	DBG_PRINTF(DEBUG_WARNING, "enter timerstamp %d\n", time(NULL));

	while(g_main_running) {
        int nfds = epoll_wait(p_table->epfd, p_table->events, BACKEND_EPOLL_ACCEPT_MAX_EVENTS, -1);

        int i;
        for (i= 0; i < nfds; ++i) {
            if (p_table->events[i].events & EPOLLIN) {
            } else {
                DBG_PRINTF(DEBUG_ERROR, "backend: %d, unknown event: %d\n",
                    p_table->fd,
                    p_table->events[i].events);
            }
        }
	}

	DBG_PRINTF(DEBUG_WARNING, "leave timestamp %d\n", time(NULL));

	exit(EXIT_SUCCESS);
}
