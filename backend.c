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
#include "user.h"
#include "domain_map.h"


extern struct ctx g_ctx;
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

    uint16_t    listen_port = g_ctx.backend_port;
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

#define BACKEND_ID_HASH(key) (*key)

DHASH_GENERATE(p_backend_work_thread_table_array, backend_sk_node, id_hash_node, seq_id, uint32_t, BACKEND_ID_HASH, uint32_t_cmp);

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

int backend_notify_make_challenge(struct backend_sk_node *sk)
{
    struct notify_node *p_notify_node = sk->p_recv_node;
    if (p_notify_node == NULL) {
        return FAIL;
    }
    sk->p_recv_node = NULL;
    p_notify_node->type = PIPE_NOTIFY_TYPE_SEND;
    p_notify_node->pos  = 0;

    uint16_t total_len = sizeof(struct backend_hdr) + sizeof(struct challenge_data);
    struct backend_hdr *p_hdr   = (struct backend_hdr *)p_notify_node->buf;
    struct challenge_data *p_data = (struct challenge_data *)(p_hdr + 1);

    sk->salt     = time(NULL);
    p_data->salt = htonl(sk->salt);

    p_hdr->magic        = htons(BACKEND_MAGIC);
    p_hdr->type         = MSG_TYPE_CHALLENGE;
    p_hdr->total_len    = htons(total_len);
    p_notify_node->end  = total_len;

    list_add_tail(&p_notify_node->list_head, &sk->send_list);
    sk->write_cb(sk);
    return SUCCESS;
}

int backend_auth_process(struct backend_sk_node *sk)
{
    struct notify_node *p_recv_node = sk->p_recv_node;
    struct backend_hdr *p_hdr = (struct backend_hdr *)(p_recv_node->buf + p_recv_node->pos);
    tlv_node_t *p_tlv = (tlv_node_t *)(p_hdr + 1);
    tlv_node_t *p_tlv_end = (tlv_node_t *)(p_recv_node->buf + p_recv_node->end);
    uint8_t                 type;
    uint16_t                length;
    uint8_t                 *value;
    char                    user_name[USER_NAME_MAX_LEN + 1] = {0};
    char                    md5[MD5_MAX_LEN + 1] = {0};
    int ret = SUCCESS;

    while(p_tlv < p_tlv_end) {
        type    = p_tlv->type;
        length  = ntohs(p_tlv->length);
        value   = p_tlv->value;

        DBG_PRINTF(DBG_NORMAL, "pos: %x, tlv type %d, length: %d\n", (uint8_t *)p_tlv - p_recv_node->buf, type, length);

        switch(type) {
        case TLV_TYPE_USER_NAME:
            if (length > USER_NAME_MAX_LEN) {
                ret = FAIL;
                goto EXIT;
            } else {
                memcpy(user_name, value, length);
                user_name[length] = 0;
            }
            break;

        case TLV_TYPE_MD5:
            if (length != 32) {
                ret = FAIL;
                goto EXIT;
            } else {
                memcpy(md5, value, length);
                md5[length] = 0;
            }
            break;

        default:
            DBG_PRINTF(DBG_WARNING, "unknown tlv type %d\n", type);
            break;
        }

        p_tlv = (tlv_node_t *)(p_tlv->value + length);
    }

    struct domain_node domain_node;
    ret = user_auth_and_get_domain(&domain_node, user_name, md5, sk->salt);
    if (ret == SUCCESS) {
        //regist domain map
        domain_node.backend_id = sk->seq_id;
        domain_node.ip = sk->ip;
        if (SUCCESS == domain_map_insert( &domain_node)) {
            sk->user_id = domain_node.user_id;

            strncpy(sk->domain, domain_node.domain, DOMAIN_MAX_LEN);
            sk->domain[DOMAIN_MAX_LEN] = 0;
            sk->ngx_domain.data = (uint8_t *)sk->domain;
            sk->ngx_domain.len = strlen(sk->domain);

            sk->status = SK_STATUS_AUTHED;
        }
    } else {
    }

EXIT:
    //make regist resp
    sk->p_recv_node = NULL;

    p_recv_node->type = PIPE_NOTIFY_TYPE_SEND;
    p_recv_node->pos  = 0;

    uint16_t                total_len = sizeof(struct backend_hdr) + sizeof(struct auth_ack_data);
    p_hdr   = (struct backend_hdr *)p_recv_node->buf;
    struct auth_ack_data *p_data = (struct auth_ack_data *)(p_hdr + 1);

    p_data->status      = htonl(ret);
    p_hdr->magic        = htons(BACKEND_MAGIC);
    p_hdr->type         = MSG_TYPE_AUTH_ACK;
    p_hdr->total_len    = htons(total_len);
    p_recv_node->end  = total_len;

    list_add_tail(&p_recv_node->list_head, &sk->send_list);
    sk->write_cb((void *)sk);

    return ret;
}

int backend_deal_read_data_process(struct backend_sk_node *sk)
{
    struct notify_node *p_recv_node = sk->p_recv_node;
    struct backend_hdr *p_hdr = (struct backend_hdr *)(p_recv_node->buf + p_recv_node->pos);

    switch (p_hdr->type) {

    case MSG_TYPE_SEND_DATA: {
        struct backend_data *p_data = (struct backend_data *)(p_hdr + 1);
        uint32_t session_id = ntohl(p_data->session_id);

        sk->p_recv_node = NULL;
        p_recv_node->pos += BACKEND_HDR_LEN + sizeof(struct backend_data);
        frontend_notify_send_data(p_recv_node, sk->seq_id, session_id);
        break;
    }

    case MSG_TYPE_HEART_BEAT:
        if (sk->status == SK_STATUS_NEW) {
            int ret = backend_notify_make_challenge(sk);
            if (ret == SUCCESS)
                sk->status = SK_STATUS_CHALLENGE;
        } else {
            backend_notify_make_heart_beat_ack(sk);
        }
        break;

    case MSG_TYPE_AUTH:
        backend_auth_process(sk);
        break;

    default:
        break;
    }

    return SUCCESS;
}

void backend_socket_read_cb(void *v)
{
    struct backend_sk_node *sk = (struct backend_sk_node *)v;

    if (sk->status > SK_STATUS_DEL_AFTER_SEND)
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

    if (sk->status > SK_STATUS_DEL_AFTER_SEND) {
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
                DBG_PRINTF(DBG_CLOSE, "seq_id %u:%d nwrite: %d\n",
                        seq_id,
                        fd,
                        nwrite);
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

    if (sk->status == SK_STATUS_DEL_AFTER_SEND) {
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

    if (sk->status == SK_STATUS_DEL) {
        DBG_PRINTF(DBG_ERROR, "seq_id %u:%d critical error alread del\n",
                sk->seq_id,
                sk->fd);
        return;
    }

    if (sk->user_id) {
        domain_map_delete(&sk->ngx_domain, sk->seq_id);
        sk->user_id = 0;
        ngx_str_null(&sk->ngx_domain);
    }

    if (sk->timer.hole != BACKEND_HEAP_INVALID_HOLE) {
        del_heap_timer(&p_table->heap, sk->timer.hole);
        sk->timer.hole = BACKEND_HEAP_INVALID_HOLE;
    }

    delete_event(p_table->epfd, sk->fd, sk, EPOLLIN | EPOLLOUT);

    close(sk->fd);
    sk->status = SK_STATUS_DEL;

    if (sk->id_hash_node.prev != NULL) {
        list_del(&sk->id_hash_node);
        sk->id_hash_node.prev = sk->id_hash_node.next = NULL;
    }

    //backend_move_node_to_list(sk, BACKEND_SOCKET_TYPE_DEL);
    if (g_main_debug >= DBG_WARNING) {
        char ip_str[30];
        uint32_t ip = htonl(sk->ip);
        DBG_PRINTF(DBG_WARNING, "exit seq_id %u:%d connect from %s:%d, ttl: %d\n",
                sk->seq_id,
                sk->fd,
                inet_ntop(AF_INET, &ip, ip_str, sizeof(ip_str)),
                sk->port,
                time(NULL) - sk->last_active);
    }
#if 0
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

#endif
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

    DBG_PRINTF(DBG_NORMAL, "del socket %u:%d free send node\n",
            sk->seq_id,
            sk->fd);

    free_backend_socket_node(sk);
}

void backend_event_connect(struct backend_work_thread_table *p_table, struct backend_sk_node *p_node)
{
    if (-1 == DHASH_INSERT(p_backend_work_thread_table_array, &p_table->hash, p_node)) {
        DBG_PRINTF(DBG_ERROR, "new socket %u:%d exist!\n",
                p_node->seq_id,
                p_node->fd);
        backend_sk_raw_del(p_node);
        return;
    }

    p_node->p_my_table      = p_table;
    p_node->user_id   = 0;
    ngx_str_null(&p_node->ngx_domain);
    p_node->status          = SK_STATUS_NEW;
    p_node->type            = BACKEND_SOCKET_TYPE_READY;
    p_node->blocked         = 0;
    p_node->read_cb         = backend_socket_read_cb;
    p_node->write_cb        = backend_socket_write_cb;
    p_node->exit_cb         = backend_socket_exit_cb;
    //p_node->del_cb          = backend_socket_del_cb;

    p_node->timer.hole      = BACKEND_HEAP_INVALID_HOLE;
    p_node->timer.timeout   = time(NULL) + BACKEND_HEAP_MAX_SIZE;
    int ret = add_heap_timer(&p_table->heap, &p_node->timer);
    if (ret != 0) {
        DBG_PRINTF(DBG_ERROR, "new socket %d seq_id %u add timer failed\n",
                p_node->seq_id,
                p_node->fd);
        backend_sk_raw_del(p_node);
        return;
    }

    struct list_table *p_list_table = &p_table->list_head[BACKEND_SOCKET_TYPE_READY];
    list_add_fe(&p_node->list_head, &p_list_table->list_head);
    p_list_table->num++;

    set_none_block(p_node->fd);
    add_event(p_table->epfd, p_node->fd, p_node, EPOLLIN);

    DBG_PRINTF(DBG_WARNING, "new socket %d seq_id %u success\n",
            p_node->seq_id,
            p_node->fd);
}

int backend_notify_make_force_offline(struct backend_sk_node *sk, struct notify_node_force_offline *p_force)
{
    struct notify_node *p_notify_node = malloc_notify_node();
    if (p_notify_node == NULL) {
        return FAIL;
    }

    p_notify_node->type = PIPE_NOTIFY_TYPE_SEND;
    p_notify_node->pos = 0;

    uint16_t total_len = sizeof(struct backend_hdr) + sizeof(struct force_offline_data);
    struct backend_hdr *p_hdr   = (struct backend_hdr *)p_notify_node->buf;
    struct force_offline_data *p_data = (struct force_offline_data *)(p_hdr + 1);

    p_hdr->magic        = htons(BACKEND_MAGIC);
    p_hdr->type         = MSG_TYPE_FORCE_OFFLINE;
    p_hdr->total_len    = htons(total_len);
    p_notify_node->end  = total_len;

    p_data->ip = htonl(p_force->ip);

    sk->status = SK_STATUS_DEL_AFTER_SEND;
    list_add_tail(&p_notify_node->list_head, &sk->send_list);
    sk->write_cb(sk);
    return 0;
}

void backend_event_force_offline(struct backend_work_thread_table *p_table, struct notify_node_force_offline *p_force)
{
    struct backend_sk_node *sk = DHASH_FIND(p_backend_work_thread_table_array, &p_table->hash, &p_force->id);
    if (sk == NULL) {
        DBG_PRINTF(DBG_NORMAL, "dst_id %u unfound!\n", p_force->id);
        return;
    }

    backend_notify_make_force_offline(sk, p_force);
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
                    break;

                case PIPE_NOTIFY_TYPE_CONNECT:
                    backend_event_connect(p_my_table, (struct backend_sk_node *)p_entry->p_node);
                    free_notify_node(p_entry);
                    break;

                case PIPE_NOTIFY_TYPE_FORCE_OFFLINE:
                    backend_event_force_offline(p_my_table, (struct notify_node_force_offline *)p_entry->buf);
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

void backend_old_process(struct backend_work_thread_table *p_table)
{
    struct heap_timer *p_top_timer = NULL;
    time_t now = time(NULL);
    time_t old_time = now - BACKEND_SOCKET_TIMEOUT;

    while((p_top_timer = top_heap_timer(&p_table->heap))) {
        if (p_top_timer->timeout > now) {
            break;
        }

        //timeout
        pop_heap_timer(&p_table->heap);
        struct backend_sk_node *p_entry = list_entry(p_top_timer, struct backend_sk_node, timer);
        if (p_entry->last_active <= old_time) {
            DBG_PRINTF(DBG_ERROR, "%u:%d, type:%d, now:%d, last_active:%d, timeout:%u\n",
                    p_entry->seq_id,
                    p_entry->fd,
                    p_entry->type,
                    now,
                    p_entry->last_active,
                    p_entry->timer.timeout);
            p_entry->exit_cb(p_entry);
        } else {
            p_entry->timer.timeout = p_entry->last_active + BACKEND_SOCKET_TIMEOUT;
            p_entry->timer.hole = BACKEND_HEAP_MAX_SIZE;
            add_heap_timer(&p_table->heap, &p_entry->timer);
        }
    }
}

void *backend_thread_socket_process(void *arg)
{
    struct backend_work_thread_table *p_table = (struct backend_work_thread_table *)arg;

    prctl(PR_SET_NAME, p_table->table_name);

    DBG_PRINTF(DBG_WARNING, "%s enter\n", p_table->table_name);

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
                if(p_table->events[i].events & EPOLLERR) {
                    sk->exit_cb(sk);
                }
                DBG_PRINTF(DBG_ERROR, "%u:%d, type:%d unknown event: %d\n",
                        sk->seq_id,
                        sk->fd,
                        sk->type,
                        p_table->events[i].events);
            }
        }

        backend_old_process(p_table);
        //backend_del_process(&p_table->list_head[MANAGE_UNUSE_SOCKET_TYPE_DEL], p_table->table_name);
    }

    DBG_PRINTF(DBG_WARNING, "leave timestamp %d\n", time(NULL));

    exit(EXIT_SUCCESS);
}

int backend_thread_pool_init()
{
    int i, ret;

    p_backend_work_thread_table_array = (struct backend_work_thread_table *)malloc(sizeof(struct backend_work_thread_table) * g_ctx.backend_work_thread);
    if (p_backend_work_thread_table_array == NULL)
        exit(EXIT_FAILURE);

    for (i = 0; i < g_ctx.backend_work_thread; i++) {
        p_backend_work_thread_table_array[i].index = i;
        pthread_mutex_init(&p_backend_work_thread_table_array[i].mutex, NULL);
        sprintf(p_backend_work_thread_table_array[i].table_name, "backend_%d", i);

        int j;
        for (j = 0; j < BACKEND_SOCKET_TYPE_MAX; j++) {
            INIT_LIST_HEAD(&p_backend_work_thread_table_array[i].list_head[j].list_head);
            p_backend_work_thread_table_array[i].list_head[j].num = 0;
        }

        DHASH_INIT(p_backend_work_thread_table_array, &p_backend_work_thread_table_array[i].hash, BACKEND_THREAD_HASH_SIZE);
        notify_table_init(&p_backend_work_thread_table_array[i].notify, "backend_thread_notify", 50000);

        backend_thread_event_init(&p_backend_work_thread_table_array[i]);

        ret = init_heap_timer(&p_backend_work_thread_table_array[i].heap, BACKEND_HEAP_MAX_SIZE);
        if (ret != 0) {
            perror("heap timer create failed!");
            exit(EXIT_FAILURE);
        }

        ret = pthread_create(&p_backend_work_thread_table_array[i].thread_id, NULL, backend_thread_socket_process, (void *)&p_backend_work_thread_table_array[i]);

        if (ret != 0) {
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
    p_notify_node->type = PIPE_NOTIFY_TYPE_CONNECT;
    p_notify_node->p_node = p_node;

    int index = p_node->seq_id % g_ctx.backend_work_thread;
    notify_table_put_head(&p_backend_work_thread_table_array[index].notify, p_notify_node);
    backend_event_notify(p_backend_work_thread_table_array[index].event_fd);
    return 0;
}

int backend_notify_force_offline(uint32_t id, uint32_t ip)
{
    struct notify_node *p_notify_node = malloc_notify_node();
    if (p_notify_node == NULL) {
        return -1;
    }
    p_notify_node->type = PIPE_NOTIFY_TYPE_FORCE_OFFLINE;
    struct notify_node_force_offline *p_force = (struct notify_node_force_offline *)p_notify_node->buf;
    p_force->id = id;
    p_force->ip = ip;

    int index = id % g_ctx.backend_work_thread;
    notify_table_put_head(&p_backend_work_thread_table_array[index].notify, p_notify_node);
    backend_event_notify(p_backend_work_thread_table_array[index].event_fd);
    return 0;
}

int backend_notify_send_data(struct notify_node *p_notify_node, uint32_t src_id, uint32_t dst_id)
{
    p_notify_node->type   = PIPE_NOTIFY_TYPE_SEND;
    p_notify_node->src_id = src_id;
    p_notify_node->dst_id = dst_id;

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

    int index = p_notify_node->dst_id % g_ctx.backend_work_thread;
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

    //g_debug_backend_id = p_node->seq_id;
    uint32_t ip = ntohl(client_addr.sin_addr.s_addr);

    p_node->id_hash_node.prev = p_node->id_hash_node.next = NULL;
    p_node->fd              = new_socket;
    p_node->ip              = ip;
    p_node->port            = ntohs(client_addr.sin_port);
    p_node->p_recv_node     = NULL;
    p_node->last_active     = time(NULL);
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
