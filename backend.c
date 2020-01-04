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
#include "frontend.h"
#include "buff.h"
#include "unique_id.h"
#include "misc.h"
#include "hash_table.h"


struct accept_socket_table g_backend_accept_socket_table;

int g_debug_backend_id = 0;
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

void backend_move_node_to_list(struct backend_sk_node *sk, int type)
{
    DBG_PRINTF(DBG_NORMAL, "seq_id %u:%d list move %d --> %d\n",
            sk->seq_id,
            sk->fd,
            sk->type,
            type);

    struct backend_work_thread_table *p_table = sk->p_my_table;
    list_move(&sk->list_head, &p_table->list_head[type].list_head);
    if (sk->type != type) {
        p_table->list_head[sk->type].num--;
        p_table->list_head[type].num++;
        sk->type = type;
    }
}

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
        DBG_PRINTF(DBG_ERROR, "create listen socket failed at %d, errnum: %d\n",
                listen_port,
                server_socket_fd);
        exit(EXIT_FAILURE);
    } else {
        DBG_PRINTF(DBG_WARNING, "create listen socket success at %d, server_socket_fd: %d\n",
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

void backend_sk_raw_del(struct backend_sk_node *sk)
{
    close(sk->fd);
    if (sk->p_recv_node)
        free_notify_node(sk->p_recv_node);

    struct list_head            *p_list = NULL;
    struct list_head            *p_next = NULL;
    list_for_each_safe(p_list, p_next, &sk->send_list) {
        struct notify_node *p_entry = list_entry(p_list, struct notify_node, list_head);
        list_del(&p_entry->list_head);
        free_notify_node(p_entry);
    }

    char ip_str[32];
    uint32_t ip = htonl(sk->ip);
    DBG_PRINTF(DBG_WARNING, "raw del socket %u:%d connect from %s:%d, last_active: %d, free send node: %d\n",
            sk->seq_id,
            sk->fd,
            inet_ntop(AF_INET, &ip, ip_str, sizeof(ip_str)),
            sk->port,
            sk->last_active);

    free_backend_socket_node(sk);
}

/*
 * 直接将心跳请求包修改成心跳响应包
 * */
int backend_notify_make_heart_beat_ack(struct backend_sk_node *sk)
{
    struct notify_node *p_notify_node = sk->p_recv_node;
    if (p_notify_node == NULL) {
        return FAIL;
    }
    sk->p_recv_node = NULL;
    p_notify_node->type = PIPE_NOTIFY_TYPE_SEND;

    struct backend_hdr *p_hdr = (struct backend_hdr *)(p_notify_node->buf + p_notify_node->pos);
    p_hdr->type = MSG_TYPE_HEART_BEAT_ACK;

    list_add_tail(&p_notify_node->list_head, &sk->send_list);
    sk->write_cb(sk);
    return 0;
}

int backend_deal_read_data_process(struct backend_sk_node *sk)
{
    struct notify_node *p_recv_node = sk->p_recv_node;
    struct backend_hdr *p_hdr = (struct backend_hdr *)(p_recv_node->buf + p_recv_node->pos);

    switch (p_hdr->type) {
    case MSG_TYPE_HEART_BEAT:
        backend_notify_make_heart_beat_ack(sk);
        break;

    case MSG_TYPE_SEND_DATA: {
        struct backend_data *p_data = (struct backend_data *)(p_hdr + 1);
        uint32_t session_id = ntohl(p_data->session_id);

        sk->p_recv_node = NULL;
        p_recv_node->pos += BACKEND_HDR_LEN + sizeof(struct backend_data);
        frontend_notify_send_data(p_recv_node, sk->seq_id, session_id);
        break;
    }

    default:
        break;
    }

    return SUCCESS;
}

void backend_socket_read_cb(void *v)
{
    struct backend_sk_node *sk = (struct backend_sk_node *)v;

    if (sk->status > SOCKET_STATUS_UNUSE_AFTER_SEND)
        return;

    sk->last_active = time(NULL);
    backend_move_node_to_list(sk, sk->type);
    while(1) {
        struct notify_node *p_recv_node = sk->p_recv_node;
        if (p_recv_node == NULL) {
            p_recv_node = malloc_notify_node();
            if (p_recv_node == NULL) {
                DBG_PRINTF(DBG_WARNING, "socket %u:%d, no avaiable space, drop data!\n",
                        sk->seq_id,
                        sk->fd);
                break;
            } else {
                p_recv_node->pos = p_recv_node->end = 0;
                sk->p_recv_node = p_recv_node;
            }
        }

        uint16_t n_recv = p_recv_node->end - p_recv_node->pos;
        int to_recv;

        if (n_recv < BACKEND_HDR_LEN) {
            to_recv = BACKEND_HDR_LEN - n_recv;
        } else {
            struct backend_hdr *p_hdr = (struct backend_hdr *)(p_recv_node->buf + p_recv_node->pos);
            if (p_hdr->magic != htons(BACKEND_MAGIC)) {
                DBG_PRINTF(DBG_ERROR, "socket %u:%d, magic error: %hu\n",
                        sk->seq_id,
                        sk->fd,
                        htons(p_hdr->magic));

                p_recv_node->end = 0;
                sk->exit_cb((void *)sk);
                break;
            }

            uint16_t total_len = ntohs(p_hdr->total_len);
            if ((total_len > (MAX_BUFF_SIZE - p_recv_node->pos))
                    || (total_len < n_recv)) {
                DBG_PRINTF(DBG_ERROR, "socket %u:%d, critical nrecv: %hu, total_len: %hu, pos: %hu, end: %hu\n",
                        sk->seq_id,
                        sk->fd,
                        n_recv,
                        total_len,
                        p_recv_node->pos,
                        p_recv_node->end);
                DBG_DUMP_HEX(DBG_NORMAL, (const uint8_t *)p_hdr, n_recv);
                sk->exit_cb((void *)sk);
                break;
            }

            if (n_recv == total_len) {
                DBG_DUMP_HEX(DBG_NORMAL, (const uint8_t *)p_recv_node->buf + p_recv_node->pos, p_recv_node->end - p_recv_node->pos);
                backend_deal_read_data_process(sk);
                continue;
            }

            to_recv = total_len - n_recv;
        }

        int nread = recv(sk->fd, sk->p_recv_node->buf + sk->p_recv_node->end, to_recv, MSG_DONTWAIT);
        if (nread > 0) {
            sk->p_recv_node->end += nread;
            continue;
        }

        if (nread == 0) {
            DBG_PRINTF(DBG_NORMAL, "socket %u:%d closed by peer\n",
                    sk->seq_id,
                    sk->fd);
            sk->exit_cb((void *)sk);
            break;
        }

        if (errno == EAGAIN) {
            DBG_PRINTF(DBG_NORMAL, "socket %u:%d need recv next!\n",
                    sk->seq_id,
                    sk->fd);
            break;
        } else if (errno == EINTR) {
            DBG_PRINTF(DBG_ERROR, "socket %u:%d need recv again!\n",
                    sk->seq_id,
                    sk->fd);
            continue;
        } else {
            DBG_PRINTF(DBG_NORMAL, "socket %u:%d errno: %d\n",
                    sk->seq_id,
                    sk->fd,
                    errno);
            sk->exit_cb((void *)sk);
            break;
        }
    }
}

void backend_socket_write_cb(void *v)
{
    struct backend_sk_node *sk = (struct backend_sk_node *)v;
    struct backend_work_thread_table *p_table = sk->p_my_table;

    int fd = sk->fd;
    uint32_t seq_id = sk->seq_id;

    if (sk->status > SOCKET_STATUS_UNUSE_AFTER_SEND) {
        DBG_PRINTF(DBG_WARNING, "seq_id %u:%d status %d!\n",
                seq_id,
                fd,
                sk->status);
        return;
    }

    if (sk->blocked)
        return;

    struct list_head            *p_list = NULL;
    struct list_head            *p_next = NULL;
    list_for_each_safe(p_list, p_next, &sk->send_list) {
        struct notify_node *p_entry = list_entry(p_list, struct notify_node, list_head);

        DBG_PRINTF(DBG_NORMAL, "seq_id %u:%d, src_id: %u, send buf pos %hu, end %hu\n",
                seq_id,
                fd,
                p_entry->type,
                p_entry->src_id,
                p_entry->pos,
                p_entry->end);

        int nwrite = 0;
        int to_write = p_entry->end - p_entry->pos;
        do {
            p_entry->pos = p_entry->pos + nwrite;
            to_write = p_entry->end - p_entry->pos;
            if (to_write == 0)
                break;

            nwrite = send(fd, p_entry->buf + p_entry->pos, to_write, 0);

            if (g_main_debug >= DBG_NORMAL) {
                log_dump_hex(p_entry->buf + p_entry->pos, to_write);
                DBG_PRINTF(DBG_CLOSE, "seq_id %u:%d nwrite: %d, front_listen_id %u\n",
                        seq_id,
                        fd,
                        nwrite,
                        sk->front_listen_id);
            }
        } while(nwrite > 0);

        if (to_write == 0) {
            DBG_PRINTF(DBG_NORMAL, "seq_id %u:%d no data to write!\n",
                    seq_id,
                    fd);

            list_del(&p_entry->list_head);
            free_notify_node(p_entry);
            continue;
        }

        if (nwrite < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                DBG_PRINTF(DBG_WARNING, "seq_id %u:%d cannot write!\n",
                        seq_id,
                        fd);
                modify_event(p_table->epfd, fd, (void *)sk, EPOLLIN | EPOLLOUT);// | EPOLLET);
                sk->blocked = 1;
                goto WRITE_EXIT;
            } else {
                DBG_PRINTF(DBG_ERROR, "seq_id %u:%d errno: %d, error msg: %s!\n",
                        seq_id,
                        fd,
                        errno,
                        strerror(errno));
                sk->exit_cb((void *)sk);
                return;
            }
        } else {
            DBG_PRINTF(DBG_ERROR, "critical seq_id %u:%d, nwrite: %d, to_write: %d\n",
                    seq_id,
                    fd,
                    nwrite,
                    to_write);
            sk->exit_cb((void *)sk);
            return;
        }
    }

    if (sk->status == SOCKET_STATUS_UNUSE_AFTER_SEND) {
        sk->exit_cb((void *)sk);
    } else {
        modify_event(p_table->epfd, fd, (void *)sk, EPOLLIN);// | EPOLLET);
    }

WRITE_EXIT:
    return;
}

void backend_socket_exit_cb(void *v)
{
    struct backend_sk_node *sk = (struct backend_sk_node *)v;
    struct backend_work_thread_table *p_table = sk->p_my_table;

    if (sk->status == SOCKET_STATUS_DEL) {
        DBG_PRINTF(DBG_ERROR, "user %u seq_id %u:%d front_listen_id:%u critical error alread del\n",
                sk->user_block_id,
                sk->seq_id,
                sk->fd,
                sk->front_listen_id);
        return;
    }

    delete_event(p_table->epfd, sk->fd, sk, EPOLLIN | EPOLLOUT);

    close(sk->fd);
    sk->status = SOCKET_STATUS_DEL;

    if (sk->id_hash_node.prev != NULL) {
        list_del(&sk->id_hash_node);
        sk->id_hash_node.prev = sk->id_hash_node.next = NULL;
    }

    backend_move_node_to_list(sk, BACKEND_SOCKET_TYPE_DEL);
    if (g_main_debug >= DBG_NORMAL) {
        char ip_str[30];
        uint32_t ip = htonl(sk->ip);
        DBG_PRINTF(DBG_WARNING, "exit seq_id %u:%d front_listen_id:%u connect from %s:%d, alive_cnt: %u, ttl: %d\n",
                sk->seq_id,
                sk->fd,
                sk->front_listen_id,
                inet_ntop(AF_INET, &ip, ip_str, sizeof(ip_str)),
                sk->port,
                sk->alive_cnt,
                time(NULL) - sk->last_active);
    }
}

void backend_socket_del_cb(void *v)
{
    struct backend_sk_node *sk = (struct backend_sk_node *)v;
    struct backend_work_thread_table *p_table = sk->p_my_table;

    if (sk->type != BACKEND_SOCKET_TYPE_DEL) {
        DBG_PRINTF(DBG_ERROR, "user %u critical error %u:%d last_active: %d type: %hhu status: %hhu\n",
                sk->seq_id,
                sk->fd,
                sk->last_active,
                sk->type,
                sk->status);
    }

    struct list_table *p_list_table = &p_table->list_head[sk->type];

    list_del(&sk->list_head);
    p_list_table->num--;

    if (sk->p_recv_node) {
        free_notify_node(sk->p_recv_node);
        sk->p_recv_node = NULL;
    }

    struct list_head            *p_list = NULL;
    struct list_head            *p_next = NULL;
    list_for_each_safe(p_list, p_next, &sk->send_list) {
        struct notify_node *p_entry = list_entry(p_list, struct notify_node, list_head);
        list_del(&p_entry->list_head);
        free_notify_node(p_entry);
    }

    DBG_PRINTF(DBG_NORMAL, "user %u del socket %u:%d free send node: %d\n",
            sk->seq_id,
            sk->fd);

    free_backend_socket_node(sk);
}

void backend_event_socket_node(struct backend_work_thread_table *p_table, struct backend_sk_node *p_node)
{
    if (-1 == DHASH_INSERT(p_backend_work_thread_table_array, &p_table->hash, p_node)) {
        DBG_PRINTF(DBG_ERROR, "new socket %u:%d exist!\n",
                p_node->seq_id,
                p_node->fd);
        backend_sk_raw_del(p_node);
        return;
    }

    p_node->p_my_table      = p_table;
    p_node->user_block_id   = 0;
    p_node->front_listen_id = 0;
    p_node->status          = SOCKET_STATUS_NEW;
    p_node->type            = BACKEND_SOCKET_TYPE_READY;
    p_node->blocked         = 0;
    p_node->read_cb         = backend_socket_read_cb;
    p_node->write_cb        = backend_socket_write_cb;
    p_node->exit_cb         = backend_socket_exit_cb;
    p_node->del_cb          = backend_socket_del_cb;

    struct list_table *p_list_table = &p_table->list_head[BACKEND_SOCKET_TYPE_READY];
    list_add_fe(&p_node->list_head, &p_list_table->list_head);
    p_list_table->num++;

    set_none_block(p_node->fd);
    add_event(p_table->epfd, p_node->fd, p_node, EPOLLIN);

    DBG_PRINTF(DBG_NORMAL, "new socket %d seq_id %u success\n",
            p_node->seq_id,
            p_node->fd);
}

void backend_event_send(struct backend_work_thread_table *p_table, struct notify_node *p_notify_node)
{
    struct backend_sk_node *sk = DHASH_FIND(p_backend_work_thread_table_array, &p_table->hash, &p_notify_node->dst_id);
    if (sk == NULL) {
        DBG_PRINTF(DBG_NORMAL, "src_id %u -> dst_id %u unfound!\n",
            p_notify_node->src_id,
            p_notify_node->dst_id); 
        free_notify_node(p_notify_node);
        //todo notify peer id not found
        
        return;
    }

    DBG_PRINTF(DBG_NORMAL, "src_id %u -> dst_id %u send!\n",
        p_notify_node->src_id,
        p_notify_node->dst_id); 
        
    list_add_tail(&p_notify_node->list_head, &sk->send_list);
    sk->write_cb(sk);
    
}

void backend_event_read_cb(void *v)
{
    struct backend_sk_node *sk = (struct backend_sk_node *)v;
    struct backend_work_thread_table *p_my_table = sk->p_my_table;

    while(1) {
        uint64_t pipe_data;
        int nread = read(sk->fd, &pipe_data, sizeof(pipe_data));
        if (nread > 0) {
            if (nread != sizeof(pipe_data)) {
                DBG_PRINTF(DBG_ERROR, "pipe %d read error\n", sk->fd);
                continue;
            }

            struct notify_node *p_entry;
            while ((p_entry = notify_table_get(&p_my_table->notify))) {
                switch (p_entry->type) {
                case PIPE_NOTIFY_TYPE_SEND:
                    backend_event_send(p_my_table, p_entry);
                    break;

                case PIPE_NOTIFY_TYPE_FREE:
                    //manage_unuse_notify_free_socket_node(p_my_table, p_entry);
                    break;

                case PIPE_NOTIFY_TYPE_SOCKET_NODE:
                    backend_event_socket_node(p_my_table, (struct backend_sk_node *)p_entry->p_node);
                    free_notify_node(p_entry);
                    break;

                case PIPE_NOTIFY_TYPE_PAIRS_INFO:
                    //manage_unuse_do_notify_3pairs_info(p_my_table, p_entry);
                    free_notify_node(p_entry);
                    break;

                default:
                    DBG_PRINTF(DBG_WARNING, "pipe %d, type: %d, dst_id %u critical unknown msg type!\n",
                            sk->fd,
                            p_entry->type,
                            p_entry->dst_id);
                    free_notify_node(p_entry);
                    break;
                }
            }
            continue;
        } else if (nread == 0) {
            DBG_PRINTF(DBG_ERROR, "critical socket %d closed by peer\n", sk->fd);
            break;
        }

        if (errno == EINTR) {
            DBG_PRINTF(DBG_ERROR, "socket %d need recv again!\n", sk->fd);
            continue;
        } else if (errno == EAGAIN) {
            DBG_PRINTF(DBG_NORMAL, "socket %d need recv next!\n", sk->fd);
            break;
        } else {
            DBG_PRINTF(DBG_ERROR, "socket %d errno: %d, error msg: %s!\n",
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
    DBG_PRINTF(DBG_WARNING, "epfd %d\n", p_table->epfd);

    p_table->event_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (p_table->event_fd < 0) {
        DBG_PRINTF(DBG_WARNING, "create event_fd failed, ret %d!\n",
                p_table->event_fd);
        exit(EXIT_FAILURE);
    }

    struct backend_sk_node *p_node = malloc_backend_socket_node();
    if (p_node == NULL) {
        DBG_PRINTF(DBG_ERROR, "event_fd failed at :%d, mem use out\n",
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

    DBG_PRINTF(DBG_WARNING, "add event_fd %d success!\n",
            p_table->event_fd);
}

void *backend_thread_socket_process(void *arg)
{
    struct backend_work_thread_table *p_table = (struct backend_work_thread_table *)arg;
    time_t last_time = time(NULL);

    prctl(PR_SET_NAME, p_table->table_name);

    DBG_PRINTF(DBG_WARNING, "%s enter timerstamp %d\n", p_table->table_name, last_time);

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
                DBG_PRINTF(DBG_ERROR, "%u:%d, type:%d unknown event: %d\n",
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

    DBG_PRINTF(DBG_WARNING, "leave timestamp %d\n", time(NULL));

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
        notify_table_init(&p_backend_work_thread_table_array[i].notify, "my_notify", 50000);

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
        DBG_PRINTF(DBG_WARNING, "event_fd %d, write error!\n",
                event_fd);
    }
}

int backend_notify_new_socket(struct backend_sk_node *p_node)
{
    struct notify_node *p_notify_node = malloc_notify_node();
    if (p_notify_node == NULL) {
        return -1;
    }
    p_notify_node->type = PIPE_NOTIFY_TYPE_SOCKET_NODE;
    p_notify_node->p_node = p_node;

    int index = p_node->seq_id % BACKEND_WORK_THREAD_NUM;
    notify_table_put_head(&p_backend_work_thread_table_array[index].notify, p_notify_node);
    backend_event_notify(p_backend_work_thread_table_array[index].event_fd);
    return 0;
}

int backend_notify_send_data(struct notify_node *p_notify_node, uint32_t src_id, uint32_t dst_id)
{
    p_notify_node->type   = PIPE_NOTIFY_TYPE_SEND;
    p_notify_node->dst_id = g_debug_backend_id;

    uint16_t control_len = BACKEND_HDR_LEN + sizeof(struct backend_data);
    if (control_len > p_notify_node->pos) {
        return -1;
    }

    uint16_t total_len = control_len + (p_notify_node->end - p_notify_node->pos);
    p_notify_node->pos -= control_len;
    struct backend_hdr *p_hdr = (struct backend_hdr *)(p_notify_node->buf + p_notify_node->pos);
    p_hdr->magic        = htons(BACKEND_MAGIC);
    p_hdr->type         = MSG_TYPE_SEND_DATA;
    p_hdr->total_len    = htons(total_len);

    struct backend_data *p_data = (struct backend_data *)(p_hdr + 1);
    p_data->session_id = htonl(src_id);

    int index = p_notify_node->dst_id % BACKEND_WORK_THREAD_NUM;
    notify_table_put_tail(&p_backend_work_thread_table_array[index].notify, p_notify_node);
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
        DBG_PRINTF(DBG_ERROR, "Accept Failed! error no: %d, error msg: %s\n",
                errno,
                strerror(errno));
        return;
    }

    struct backend_sk_node *p_node = malloc_backend_socket_node();
    if (p_node == NULL) {
        char ip_str[32];
        DBG_PRINTF(DBG_ERROR, "new socket %d connect from %s:%hu failed\n",
                new_socket,
                inet_ntop(AF_INET, &client_addr.sin_addr.s_addr, ip_str, sizeof(ip_str)),
                client_addr.sin_port);
        close(new_socket);
        return;
    }

    g_debug_backend_id = p_node->seq_id;
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
        DBG_PRINTF(DBG_CLOSE, "new socket %d seq_id %u connect from %s:%hu failed\n",
                new_socket,
                p_node->seq_id,
                inet_ntop(AF_INET, &client_addr.sin_addr.s_addr, ip_str, sizeof(ip_str)),
                client_addr.sin_port);
        return;
    } else {
        char ip_str[32];
        DBG_PRINTF(DBG_NORMAL, "new socket %d seq_id %u connect from %s:%hu success\n",
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

    DBG_PRINTF(DBG_WARNING, "enter timerstamp %d\n", time(NULL));

    while(g_main_running) {
        int nfds = epoll_wait(p_table->epfd, p_table->events, BACKEND_ACCEPT_EPOLL_MAX_EVENTS, -1);

        int i;
        for (i= 0; i < nfds; ++i) {
            if (p_table->events[i].events & EPOLLIN) {
                backend_socket_handle_accpet_cb();
            } else {
                DBG_PRINTF(DBG_ERROR, "backend: %d, unknown event: %d\n",
                        p_table->fd,
                        p_table->events[i].events);
            }
        }
    }

    DBG_PRINTF(DBG_WARNING, "leave timestamp %d\n", time(NULL));

    exit(EXIT_SUCCESS);
}
