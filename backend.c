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
#include <sys/eventfd.h>
#include <arpa/inet.h>

#include "main.h"
#include "log.h"
#include "backend.h"
#include "buff.h"
#include "unique_id.h"
#include "misc.h"
#include "hash_table.h"


struct accept_socket_table g_backend_accept_socket_table;

#if 1

struct buff_table g_backend_socket_buff_table;

void backend_socket_buff_table_init()
{
    buff_table_init(&g_backend_socket_buff_table, BACKEND_SOCKET_MAX_NUM, sizeof(struct backend_sk_node), "g_backend_socket_buff_table");
}

inline struct backend_sk_node *malloc_backend_socket_node()
{
    struct backend_sk_node *p_node = (struct backend_sk_node *)buff_table_malloc_node(&g_backend_socket_buff_table);
    if (p_node)
        p_node->seq_id = unique_id_get();
    return p_node;
}

inline void free_backend_socket_node(struct backend_sk_node *p_node)
{
    unique_id_put(p_node->seq_id);
    buff_table_free_node(&g_backend_socket_buff_table, &p_node->list_head);
}

void display_g_backend_buff_table()
{
    display_buff_table(&g_backend_socket_buff_table);
}

#endif

int backend_accept_init()
{
    struct accept_socket_table *p_table = (struct accept_socket_table *)&g_backend_accept_socket_table;

    p_table->events = (struct epoll_event *)malloc(sizeof(struct epoll_event) * BACKEND_ACCEPT_EPOLL_MAX_EVENTS);
    if (p_table->events == NULL)
	    exit(EXIT_FAILURE);

    p_table->epfd = epoll_create(BACKEND_ACCEPT_EPOLL_MAX_EVENTS);

    uint16_t    listen_port = BACKEND_PORT;
    int server_socket_fd = create_listen_socket(listen_port, BACKEND_ACCEPT_LISTEN_BACKLOG);
    if (server_socket_fd < 0) {
        DBG_PRINTF(DEBUG_ERROR, "create listen socket failed at %d, errnum: %d\n",
            listen_port,
            server_socket_fd);
	    exit(EXIT_FAILURE);
    } else {
        DBG_PRINTF(DEBUG_WARNING, "create listen socket success at %d, server_socket_fd: %d\n",
            listen_port,
            server_socket_fd);
    }

    p_table->fd              = server_socket_fd;

    set_none_block(p_table->fd);
    add_event(p_table->epfd, p_table->fd, NULL, EPOLLIN);

    return 0;
}

struct backend_work_thread_table *p_backend_work_thread_table_array = NULL;

inline uint32_t  unuse_hash(uint32_t *key)
{
    return ((*key) / (BACKEND_WORK_THREAD_NUM)) % (p_backend_work_thread_table_array[0].hash.size);
}

DHASH_GENERATE(p_backend_work_thread_table_array, backend_sk_node, id_hash_node, seq_id, uint32_t, unuse_hash, uint32_t_cmp);

void backend_event_read_cb(void *v)
{
    struct backend_sk_node *sk = (struct backend_sk_node *)v;    
    struct backend_work_thread_table *p_my_table = sk->p_my_table;
    
    while(1) {
        uint64_t pipe_data;
        int nread = read(sk->fd, &pipe_data, sizeof(pipe_data));
        if (nread > 0) {
            if (nread != sizeof(pipe_data)) {
                DBG_PRINTF(DEBUG_ERROR, "pipe %d read error\n", sk->fd);
                continue;
            }

            struct socket_notify_block *p_entry;
            while((p_entry = my_notify_table_get(&p_my_table->notify))) {
                switch(p_entry->type) {
                case PIPE_NOTIFY_TYPE_SEND:
                    //manage_unuse_notify_send_data(p_my_table, p_entry);
                    break;

                case PIPE_NOTIFY_TYPE_FREE:
                    //manage_unuse_notify_free_socket_node(p_my_table, p_entry);
                    break;

                case PIPE_NOTIFY_TYPE_SOCKET_NODE:
                    //manage_unuse_notify_add_new_socket_node(p_my_table, (struct manage_info_t *)p_entry->p_node);
                    free_notify_node(p_entry);
                    break;

                case PIPE_NOTIFY_TYPE_PAIRS_INFO:
                    //manage_unuse_do_notify_3pairs_info(p_my_table, p_entry);
                    free_notify_node(p_entry);
                    break;

                default:
                    DBG_PRINTF(DEBUG_WARNING, "pipe %d, type: %d, dst_id %u critical unknown msg type!\n",                                 
                            sk->fd,
                            p_entry->type,
                            p_entry->dst_id);
                    free_notify_node(p_entry);
                    break;
                }

            }
            continue;
        } else if (nread == 0) {
            DBG_PRINTF(DEBUG_ERROR, "critical socket %d closed by peer\n", sk->fd);
            break;
        }

        if (errno == EINTR) {
            DBG_PRINTF(DEBUG_ERROR, "socket %d need recv again!\n", sk->fd);
            continue;
        } else if (errno == EAGAIN) {
            DBG_PRINTF(DEBUG_NORMAL, "socket %d need recv next!\n", sk->fd);
            break;
        } else {
            DBG_PRINTF(DEBUG_ERROR, "socket %d errno: %d, error msg: %s!\n",
                    sk->fd,
                    errno,
                    strerror(errno));
            break;
        }
    }
}

void backend_thread_event_init(struct backend_work_thread_table *p_table)
{        
    p_table->events = (struct epoll_event *)malloc(sizeof(struct epoll_event) * BACKEND_THREAD_EPOLL_MAX_EVENTS);
    if (p_table->events == NULL)
	    exit(EXIT_FAILURE);	

    p_table->epfd = epoll_create(BACKEND_THREAD_EPOLL_MAX_EVENTS);    
    DBG_PRINTF(DEBUG_WARNING, "epfd %d\n", p_table->epfd);

    p_table->event_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (p_table->event_fd < 0) {
        DBG_PRINTF(DEBUG_WARNING, "create event_fd failed, ret %d!\n",
            p_table->event_fd);
	    exit(EXIT_FAILURE);	
    }
    
    struct backend_sk_node *p_node = malloc_backend_socket_node();
    if (p_node == NULL) {
        DBG_PRINTF(DEBUG_ERROR, "event_fd failed at :%d, mem use out\n",
            p_table->event_fd);
        close(p_table->event_fd);
	    exit(EXIT_FAILURE);	
    }

    p_node->fd              = p_table->event_fd;
    p_node->ip              = 0;
    p_node->port            = 0;
    p_node->p_my_table      = p_table;
    p_node->p_recv_node     = NULL;
    p_node->last_active     = time(NULL);
    p_node->status          = SOCKET_STATUS_NEW;
    p_node->type            = BACKEND_SOCKET_TYPE_READY;
    p_node->read_cb         = backend_event_read_cb;
    p_node->write_cb        = NULL;
    p_node->exit_cb         = NULL;
    p_node->del_cb          = NULL;    
    
    set_none_block(p_node->fd);
    add_event(p_table->epfd, p_node->fd, p_node, EPOLLIN);

    DBG_PRINTF(DEBUG_WARNING, "add event_fd %d success!\n",
        p_table->event_fd);
}

void *backend_thread_socket_process(void *arg)
{
    struct backend_work_thread_table *p_table = (struct backend_work_thread_table *)arg;
    time_t last_time = time(NULL);

    prctl(PR_SET_NAME, p_table->table_name);

	DBG_PRINTF(DEBUG_WARNING, "%s enter timerstamp %d\n", p_table->table_name, last_time);
    
	while(g_main_running) {
        int nfds = epoll_wait(p_table->epfd, p_table->events, BACKEND_THREAD_EPOLL_MAX_EVENTS, 1 * 1000);

        int i;
        for( i= 0; i < nfds; ++i) {
			struct backend_sk_node *sk = (struct backend_sk_node *)(p_table->events[i].data.ptr);

            if(p_table->events[i].events & EPOLLIN) {
                sk->read_cb((void *)sk);
            } else if(p_table->events[i].events & EPOLLOUT) {
                    sk->blocked = 0;
                    sk->write_cb((void *)sk);
            } else {
                DBG_PRINTF(DEBUG_ERROR, "%u:%d, type:%d unknown event: %d\n",
                    sk->seq_id,
                    sk->fd,
                    sk->type,
                    p_table->events[i].events); 
            }
        }
        
#if 0
        time_t now = time(NULL);
        if ((now - last_time) > LT_MANAGE_SOCKET_CHECK_PERIOD_SECONDS)
        {
            last_time = now;
            manage_old_process(&p_table->list_head[MANAGE_UNUSE_SOCKET_TYPE_READY], MANAGE_UNUSE_SOCKET_TYPE_READY, LT_MANAGE_SOCKET_TIMEOUT_MAX_SECONDS, p_table->table_name);
        }

        //pthread_mutex_unlock(&p_table->mutex);
        
        manage_del_process(&p_table->list_head[MANAGE_UNUSE_SOCKET_TYPE_DEL], p_table->table_name);
#endif
	}

	DBG_PRINTF(DEBUG_WARNING, "leave timestamp %d\n", time(NULL));

	exit(EXIT_SUCCESS);	
}

int backend_thread_pool_init()
{
    int i, res;

    p_backend_work_thread_table_array = (struct backend_work_thread_table *)malloc(sizeof(struct backend_work_thread_table) * BACKEND_WORK_THREAD_NUM);
    if (p_backend_work_thread_table_array == NULL)
	    exit(EXIT_FAILURE);

    for (i = 0; i < BACKEND_WORK_THREAD_NUM; i++) {
        p_backend_work_thread_table_array[i].index = i;
        pthread_mutex_init(&p_backend_work_thread_table_array[i].mutex, NULL);
        sprintf(p_backend_work_thread_table_array[i].table_name, "backend_%d", i);

        int j;
        for (j = 0; j < BACKEND_SOCKET_TYPE_MAX; j++) {
            INIT_LIST_HEAD(&p_backend_work_thread_table_array[i].list_head[j].list_head);
            p_backend_work_thread_table_array[i].list_head[j].num = 0;
        }

        DHASH_INIT(p_backend_work_thread_table_array, &p_backend_work_thread_table_array[i].hash, BACKEND_THREAD_HASH_SIZE);
        my_notify_table_init(&p_backend_work_thread_table_array[i].notify, "my_notify", 50000);

        backend_thread_event_init(&p_backend_work_thread_table_array[i]);

        res = pthread_create(&p_backend_work_thread_table_array[i].thread_id, NULL, backend_thread_socket_process, (void *)&p_backend_work_thread_table_array[i]);

        if (res != 0) {
            perror("Thread creation failed!");
            exit(EXIT_FAILURE);
        }
    }
    return 0;
}

int backend_init()
{
    backend_socket_buff_table_init();
    backend_accept_init();
    backend_thread_pool_init();
    return 0;
}

inline void backend_event_notify(int event_fd)
{
    uint64_t notify = 1;
    if (write(event_fd, &notify, sizeof(notify)) < 0) {
        DBG_PRINTF(DEBUG_WARNING, "event_fd %d, write error!\n",
            event_fd);
    }
}

int backend_notify_new_socket(struct backend_sk_node *p_node)
{
    struct socket_notify_block *p_notify_node = malloc_notify_node();
    if (p_notify_node == NULL) {
        return -1;
    }
    p_notify_node->type = PIPE_NOTIFY_TYPE_SOCKET_NODE;
    p_notify_node->p_node = p_node;

    int index = p_node->seq_id % BACKEND_WORK_THREAD_NUM;
    my_notify_table_put_head(&p_backend_work_thread_table_array[index].notify, p_notify_node);
    backend_event_notify(p_backend_work_thread_table_array[index].event_fd);
    return 0;
}

void backend_socket_handle_accpet_cb()
{
    struct accept_socket_table *p_table = (struct accept_socket_table *)&g_backend_accept_socket_table;
    struct sockaddr_in  client_addr;
    socklen_t           length          = sizeof(client_addr);
    int                 new_socket      = accept(p_table->fd, (struct sockaddr*)&client_addr, &length);

    if (new_socket < 0) {
        DBG_PRINTF(DEBUG_ERROR, "Accept Failed! error no: %d, error msg: %s\n",
            errno,
            strerror(errno));
        return;
    }

    struct backend_sk_node *p_node = malloc_backend_socket_node();
    if (p_node == NULL) {
        char ip_str[32];
        DBG_PRINTF(DEBUG_ERROR, "new socket %d connect from %s:%hu failed\n",
            new_socket,
            inet_ntop(AF_INET, &client_addr.sin_addr.s_addr, ip_str, sizeof(ip_str)),
            client_addr.sin_port);
        close(new_socket);
        return;
    }

    uint32_t ip = ntohl(client_addr.sin_addr.s_addr);

    p_node->mac_hash_node.prev = p_node->mac_hash_node.next = NULL;
    p_node->id_hash_node.prev = p_node->id_hash_node.next = NULL;
    p_node->fd              = new_socket;
    p_node->ip              = ip;
    p_node->port            = ntohs(client_addr.sin_port);
    p_node->p_recv_node     = NULL;
    p_node->last_active     = time(NULL);
    p_node->alive_cnt       = 0;
    p_node->quality         = 0;
    p_node->blocked         = 0;

    INIT_LIST_HEAD(&p_node->send_list);

    if (backend_notify_new_socket(p_node) == -1) {
        close(new_socket);
        free_backend_socket_node(p_node);

        char ip_str[32];
        DBG_PRINTF(DEBUG_CLOSE, "new socket %d seq_id %u connect from %s:%hu failed\n",
            new_socket,
            p_node->seq_id,
            inet_ntop(AF_INET, &client_addr.sin_addr.s_addr, ip_str, sizeof(ip_str)),
            client_addr.sin_port);
        return;
    } else {
        char ip_str[32];
        DBG_PRINTF(DEBUG_NORMAL, "new socket %d seq_id %u connect from %s:%hu success\n",
            new_socket,
            p_node->seq_id,
            inet_ntop(AF_INET, &client_addr.sin_addr.s_addr, ip_str, sizeof(ip_str)),
            client_addr.sin_port);
    }
}

void *backend_accept_process(void *arg)
{
    struct accept_socket_table *p_table = &g_backend_accept_socket_table;

    prctl(PR_SET_NAME, __FUNCTION__);

	DBG_PRINTF(DEBUG_WARNING, "enter timerstamp %d\n", time(NULL));

	while(g_main_running) {
        int nfds = epoll_wait(p_table->epfd, p_table->events, BACKEND_ACCEPT_EPOLL_MAX_EVENTS, -1);

        int i;
        for (i= 0; i < nfds; ++i) {
            if (p_table->events[i].events & EPOLLIN) {
                backend_socket_handle_accpet_cb();
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
