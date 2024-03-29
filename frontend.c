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
#include <assert.h>

#include "main.h"
#include "log.h"
#include "frontend.h"
#include "backend.h"
#include "buff.h"
#include "unique_id.h"
#include "misc.h"
#include "hash_table.h"
#include "domain_map.h"


extern struct ctx g_ctx;

struct frontend_accept_socket_table g_frontend_accept_socket_table;

const ngx_str_t g_ngx_str_host = ngx_string("Host");
const ngx_str_t g_ngx_str_content_type = ngx_string("Content-type");
const ngx_str_t g_ngx_str_user_agent = ngx_string("User-agent");
const ngx_str_t g_ngx_str_content_length = ngx_string("Content-length");

void frontend_listen_socket_handle_accpet_cb(void *v);
#if 1

struct buff_table g_frontend_socket_buff_table;

void frontend_socket_buff_table_init()
{
    buff_table_init(&g_frontend_socket_buff_table, FRONTEND_SOCKET_MAX_NUM, sizeof(struct frontend_sk_node), "g_frontend_socket_buff_table");
}

inline struct frontend_sk_node *malloc_frontend_socket_node()
{
    struct frontend_sk_node *p_node = (struct frontend_sk_node *)buff_table_malloc_node(&g_frontend_socket_buff_table);
    if (p_node)
        p_node->seq_id = unique_id_get();
    return p_node;
}

inline void free_frontend_socket_node(struct frontend_sk_node *p_node)
{
    unique_id_put(p_node->seq_id);
    buff_table_free_node(&g_frontend_socket_buff_table, &p_node->list_head);
}

void display_g_frontend_buff_table()
{
    display_buff_table(&g_frontend_socket_buff_table);
}

#endif

void frontend_move_node_to_list(struct frontend_sk_node *sk, int type)
{
    DBG_PRINTF(DBG_NORMAL, "seq_id %u:%d list move %d --> %d\n",
            sk->seq_id,
            sk->fd,
            sk->type,
            type);

    struct frontend_work_thread_table *p_table = sk->p_my_table;
    list_move(&sk->list_head, &p_table->list[type].list_head);
    if (sk->type != type) {
        p_table->list[sk->type].num--;
        p_table->list[type].num++;
        sk->type = type;
    }
}

#if 2

struct buff_table g_frontend_listen_socket_buff_table;

void frontend_listen_socket_buff_table_init()
{
    buff_table_init(&g_frontend_listen_socket_buff_table, FRONTEND_LISTEN_SOCKET_MAX_NUM, sizeof(struct frontend_listen_sk_node), "g_frontend_listen_socket_buff_table");
}

inline struct frontend_listen_sk_node *malloc_frontend_listen_socket_node()
{
    return (struct frontend_listen_sk_node *)buff_table_malloc_node(&g_frontend_listen_socket_buff_table);
}

inline void free_frontend_listen_socket_node(struct frontend_listen_sk_node *p_node)
{
    buff_table_free_node(&g_frontend_listen_socket_buff_table, &p_node->list_head);
}

void display_g_frontend_listen_socket_buff_table()
{
    display_buff_table(&g_frontend_listen_socket_buff_table);
}

#endif

int frontend_listen_port_init(uint16_t listen_port)
{
    struct frontend_accept_socket_table *p_table = (struct frontend_accept_socket_table *)&g_frontend_accept_socket_table;
    int server_socket_fd = create_listen_socket(listen_port, FRONTEND_ACCEPT_LISTEN_BACKLOG);

    if (server_socket_fd < 0) {
        DBG_PRINTF(DBG_ERROR, "create listen socket failed at %d, errnum: %d\n",
                listen_port,
                server_socket_fd);
        return FAIL;
    } else {
        DBG_PRINTF(DBG_WARNING, "create listen socket success at %d, server_socket_fd: %d\n",
                listen_port,
                server_socket_fd);
    }

    struct frontend_listen_sk_node *p_node = malloc_frontend_listen_socket_node();
    if (p_node == NULL) {
        DBG_PRINTF(DBG_WARNING, "malloc error\n");
        close(server_socket_fd);
        return FAIL;
    }

    p_node->fd = server_socket_fd;
    p_node->my_port = listen_port;
    p_node->backend_id = 0;
    p_node->accept_cb = frontend_listen_socket_handle_accpet_cb;

    set_none_block(p_node->fd);
    add_event(p_table->epfd, p_node->fd, p_node, EPOLLIN);

    return 0;
}

int frontend_accept_init()
{
    struct frontend_accept_socket_table *p_table = (struct frontend_accept_socket_table *)&g_frontend_accept_socket_table;

    p_table->events = (struct epoll_event *)malloc(sizeof(struct epoll_event) * FRONTEND_ACCEPT_EPOLL_MAX_EVENTS);
    if (p_table->events == NULL)
        exit(EXIT_FAILURE);

    p_table->epfd = epoll_create(FRONTEND_ACCEPT_EPOLL_MAX_EVENTS);

    if (FAIL == frontend_listen_port_init(g_ctx.http_port))
        exit(EXIT_FAILURE);
    if (FAIL == frontend_listen_port_init(g_ctx.https_port))
        exit(EXIT_FAILURE);

    return 0;
}

struct frontend_work_thread_table *p_frontend_work_thread_table_array = NULL;

inline uint32_t frontend_hash(uint32_t *key)
{
    return (*key) / (g_ctx.frontend_work_thread);
}

DHASH_GENERATE(p_frontend_work_thread_table_array, frontend_sk_node, id_hash_node, seq_id, uint32_t, frontend_hash, uint32_t_cmp);

void frontend_sk_raw_del(struct frontend_sk_node *sk)
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

    free_frontend_socket_node(sk);
}

int frontend_http_relay_data(struct frontend_sk_node *sk)
{
    struct notify_node *p_notify_node = sk->p_recv_node;
    sk->p_recv_node = NULL;

    return backend_notify_send_data(p_notify_node, sk->seq_id, sk->backend_id);
}

int http_parse_block_init(struct frontend_sk_node *sk)
{
    struct http_parse_block     *p_parse_block = &sk->parse_block;
    struct notify_node  *p_recv_node = sk->p_recv_node;

    p_parse_block->start = p_parse_block->pos = p_recv_node->pos;

    ngx_str_null(&p_parse_block->request_line);
    ngx_str_null(&p_parse_block->host);
    ngx_str_null(&p_parse_block->user_agent);
    p_parse_block->done_map = 0;

    sk->err_type = CON_ERR_TYPE_NONE;
    return SUCCESS;
}

#define CHECK_CRLF(header, len)                                 \
    (((len) == 1 && header[0] == '\n') ||                         \
     ((len) == 2 && header[0] == '\r' && header[1] == '\n'))

int http_parse_headers(struct frontend_sk_node *sk)
{
    struct http_parse_block     *p_parse_block = &sk->parse_block;
    struct notify_node  *p_recv_node = sk->p_recv_node;

    assert(p_recv_node != NULL);

    char    *buffer = (char *)p_recv_node->buf;
    char    *ptr    = NULL;
    int     start   = p_parse_block->start;
    int     pos     = p_parse_block->pos;
    int     end     = p_recv_node->end;

    assert(pos >= start);
    assert(pos <= end);

    while(pos < end) {
        ptr = (char *)memchr(buffer + pos, '\n', end - pos);
        if (ptr) {
            char    *p_start = buffer + start;
            int     len      = ptr - p_start + 1;

            if (len < 1) {
                sk->err_type = CON_ERR_TYPE_INNER;
                return FAIL;
            }

            start += len;
            pos = start;

            if (CHECK_CRLF(p_start, len)) {
                p_parse_block->start = start;
                p_parse_block->pos   = pos;

                return SUCCESS;
            }

            ngx_str_t header = {
                .data = (uint8_t *)p_start,
                .len = len
            };

            if (g_main_debug >= DBG_NORMAL) {
                char header_buf[200];
                DBG_PRINTF(DBG_WARNING, "header [%s]\n",
                        ngx_print(header_buf, 200, &header));
            }

            if (p_parse_block->request_line.data == NULL) {
                p_parse_block->request_line = header;
                p_parse_block->done_map |= bit_request;
            } else {
                char *p_colon;

                p_colon = (char *)memchr(p_start, ':', len);
                if (!p_colon) {
                    sk->err_type = CON_ERR_TYPE_INNER;
                    return FAIL;
                }

                int header_len = p_colon - p_start;
                if (header_len < 1) {
                    sk->err_type = CON_ERR_TYPE_INNER;
                    return FAIL;
                }

                ngx_str_t header_name = {
                    .data = (uint8_t *)p_start,
                    .len = header_len
                };
                ngx_str_t header_value = {
                    .data = (uint8_t *)p_colon + 1,
                    .len = len - header_len - 1
                };

                if (g_main_debug >= DBG_NORMAL) {
                    char header_name_buf[200];
                    char header_value_buf[200];
                    DBG_PRINTF(DBG_WARNING, "header_name [%s], value [%s]\n",
                            ngx_print(header_name_buf, 200, &header_name),
                            ngx_print(header_value_buf, 200, &header_value));
                }
                if (ngx_casecmp(&header_name, &g_ngx_str_host) == 0) {
                    p_parse_block->host = header_value;
                    p_parse_block->done_map |= bit_host;
                } else if (ngx_casecmp(&header_name, &g_ngx_str_user_agent) == 0) {
                    p_parse_block->user_agent = header_value;
                    p_parse_block->done_map |= bit_user_agent;
                }
            }
        } else {
            break;
        }
    }

    p_parse_block->pos    = end;
    p_parse_block->start  = start;
    return NEED_MORE;
}

int https_parse_hello(struct frontend_sk_node *sk)
{
    struct http_parse_block *p_parse_block = &sk->parse_block;
    struct notify_node  *p_recv_node = sk->p_recv_node;

    assert(p_recv_node != NULL);

    int data_len = p_recv_node->end - p_recv_node->pos;

    if (data_len < sizeof(struct tls_hdr)) {
        return NEED_MORE;
    }

    struct tls_hdr *p_hdr = (struct tls_hdr *)(p_recv_node->buf + p_recv_node->pos);


    if (TLS_CONTENT_TYPE_HANDSHAKE != p_hdr->content_type) {
        sk->err_type = CON_ERR_TYPE_INNER;
        return FAIL;
    }

    uint16_t length = ntohs(p_hdr->length);

    if (data_len < (sizeof(struct tls_hdr) + length)) {
        return NEED_MORE;
    }

    struct handshake_hdr *p_handshake_hdr = (struct handshake_hdr *)(p_hdr + 1);

    if (g_main_debug >= DBG_WARNING) {
        uint32_t length = p_handshake_hdr->length;
        DBG_PRINTF(DBG_WARNING, "handshake type [%hhu], length [%u]\n",
                p_handshake_hdr->type,
                ntohl(length));
    }
    if (HANDSHAKE_TYPE_CLIENT_HELLO != p_handshake_hdr->type) {
        DBG_PRINTF(DBG_WARNING, "unknown handshake type [%u]\n",
                p_handshake_hdr->type);
        sk->err_type = CON_ERR_TYPE_INNER;
        return FAIL;
    }

    uint8_t *p_lv_pos = (uint8_t *)(p_handshake_hdr + 1);
    uint8_t *p_lv_end = p_recv_node->buf + p_recv_node->end;


    //session_id
    uint8_t session_id_length = *(uint8_t *)p_lv_pos;
    p_lv_pos += 1 + session_id_length;
    if (p_lv_pos > p_lv_end) {
        DBG_PRINTF(DBG_WARNING, "session_id_length [%u]\n",
                session_id_length);
        sk->err_type = CON_ERR_TYPE_INNER;
        return FAIL;
    }

    //cipher suites
    uint16_t cipher_suites_length = ntohs(*(uint16_t *)p_lv_pos);
    p_lv_pos += 2 + cipher_suites_length;
    if (p_lv_pos > p_lv_end) {
        DBG_PRINTF(DBG_WARNING, "cipher_suites_length [%u]\n",
                cipher_suites_length);
        sk->err_type = CON_ERR_TYPE_INNER;
        return FAIL;
    }

    //compression_methods_id
    uint8_t compression_methods_length = *(uint8_t *)p_lv_pos;
    p_lv_pos += 1 + compression_methods_length;
    if (p_lv_pos > p_lv_end) {
        DBG_PRINTF(DBG_WARNING, "compression_methods_length [%u]\n",
                compression_methods_length);
        sk->err_type = CON_ERR_TYPE_INNER;
        return FAIL;
    }

    //extensions length
    uint16_t extensions_length = ntohs(*(uint16_t *)p_lv_pos);

    uint8_t *p_extensions_start = p_lv_pos + 2;
    uint8_t *p_extensions_end = p_extensions_start + extensions_length;

    if (p_extensions_end > p_lv_end) {
        DBG_PRINTF(DBG_WARNING, "extensions_length [%u]\n",
                extensions_length);
        sk->err_type = CON_ERR_TYPE_INNER;
        return FAIL;
    }

    while(p_extensions_start < p_extensions_end) {
        struct tlv_hdr *p_tlv = (struct tlv_hdr *)p_extensions_start;

        uint16_t type = ntohs(p_tlv->type);
        uint16_t length = ntohs(p_tlv->length);

        p_extensions_start += sizeof(struct tlv_hdr) + length;
        if (p_extensions_start > p_extensions_end) {
            sk->err_type = CON_ERR_TYPE_INNER;
            return FAIL;
        }

        switch(type) {

        case EXTENSION_TYPE_SERVER_NAME: {
            uint16_t *p_list_length = (uint16_t *)p_tlv->value;
            uint16_t list_length = *p_list_length;
            list_length = ntohs(list_length);
            if (list_length <= sizeof(struct tlv_hdr)) {
                sk->err_type = CON_ERR_TYPE_INNER;
                return FAIL;
            }

            tlv_node_t *p_server_name_tlv = (tlv_node_t *)(p_tlv->value + 2);

            if (p_server_name_tlv->type != 0) {
                sk->err_type = CON_ERR_TYPE_INNER;
                return FAIL;
            }

            uint16_t server_name_length = ntohs(p_server_name_tlv->length);
            if (server_name_length > DOMAIN_MAX_LEN) {
                sk->err_type = CON_ERR_TYPE_INNER;
                return FAIL;
            }

            p_parse_block->host.data = p_server_name_tlv->value;
            p_parse_block->host.len = server_name_length;
            p_parse_block->done_map |= bit_host;

            return SUCCESS;
            break;
        }

        default:
            break;
        }

    }

    sk->err_type = CON_ERR_TYPE_INNER;
    return FAIL;
}

/*
 * parse http header
 * according to host, deliver package to guest
 */
int frontend_http_process(struct frontend_sk_node *sk)
{
    int ret = SUCCESS;

    if (sk->state == HTTP_STATE_INIT) {
        http_parse_block_init(sk);
        if (sk->my_port == g_ctx.http_port)
            sk->state = HTTP_STATE_REQUEST;
        else 
            sk->state = HTTP_STATE_HELLO;
    }

    switch(sk->state) {

    case HTTP_STATE_HELLO:
        ret = https_parse_hello(sk);
        if (ret == FAIL) {
            return ret;
        }

        if ((sk->parse_block.done_map & bit_host) == bit_host) {
            char host_buf[200];
            DBG_PRINTF(DBG_WARNING, "host [%s]\n",
                    ngx_print(host_buf, 200, &sk->parse_block.host));
            if (chomp_space_ngx_str(&sk->parse_block.host) < 0)
                return FAIL;

            struct domain_node domain_node;
            ret = domain_map_query(&domain_node, &sk->parse_block.host);
            if (ret == FAIL)
                return ret;

            sk->state = HTTP_STATE_RELAY;

            sk->user_id = domain_node.user_id;
            sk->backend_id = domain_node.backend_id;
            ret = frontend_http_relay_data(sk);
        }
        break;

    case HTTP_STATE_REQUEST:
        ret = http_parse_headers(sk);
        if (ret == FAIL) {
            return ret;
        }

        if ((sk->parse_block.done_map & bit_done) == bit_done) {
            if (g_main_debug >= DBG_NORMAL) {
                char header_name_buf[200];
                char header_value_buf[200];
                DBG_PRINTF(DBG_WARNING, "header_name [%s], value [%s]\n",
                        ngx_print(header_name_buf, 200, &sk->parse_block.host),
                        ngx_print(header_value_buf, 200, &sk->parse_block.request_line));
            }
            if (chomp_space_ngx_str(&sk->parse_block.host) < 0) {
                sk->err_type = CON_ERR_TYPE_INNER;
                return FAIL;
            }

            struct domain_node domain_node;
            ret = domain_map_query(&domain_node, &sk->parse_block.host);
            if (ret == FAIL) {
                sk->err_type = CON_ERR_TYPE_CLIENT_OFFLINE;
                return ret;
            }

            sk->state = HTTP_STATE_RELAY;

            sk->user_id = domain_node.user_id;
            sk->backend_id = domain_node.backend_id;
            ret = frontend_http_relay_data(sk);
        } else {
            //parse done, but can not find host
            if (ret == SUCCESS)
                return FAIL;
        }
        break;

    case HTTP_STATE_RELAY:
        ret = frontend_http_relay_data(sk);
        break;

    default:
        break;

    }

    return ret;
}

void frontend_socket_read_cb(void *v)
{
    struct frontend_sk_node *sk = (struct frontend_sk_node *)v;

    if (sk->status > SOCKET_STATUS_EXIT_AFTER_SEND)
        return;

    sk->last_active = time(NULL);
    frontend_move_node_to_list(sk, sk->type);
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
                p_recv_node->pos = p_recv_node->end = BACKEND_RESERVE_HDR_SIZE;
                sk->p_recv_node = p_recv_node;
            }
        }

        uint16_t to_recv = MAX_BUFF_SIZE - p_recv_node->end;

        int nread = recv(sk->fd, p_recv_node->buf + p_recv_node->end, to_recv, MSG_DONTWAIT);
        if (nread > 0) {
            p_recv_node->end += nread;
            if (FAIL == frontend_http_process(sk)) {
                if (sk->err_type == CON_ERR_TYPE_INNER)
                    log_dump_hex(p_recv_node->buf + p_recv_node->pos, p_recv_node->end - p_recv_node->pos);
                sk->exit_cb(sk);
                return;
            }
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

void frontend_socket_write_cb(void *v)
{
    struct frontend_sk_node *sk = (struct frontend_sk_node *)v;
    struct frontend_work_thread_table *p_table = sk->p_my_table;

    int fd = sk->fd;
    uint32_t seq_id = sk->seq_id;

    if (sk->status > SOCKET_STATUS_EXIT_AFTER_SEND) {
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

    if (sk->status == SOCKET_STATUS_EXIT_AFTER_SEND) {
        sk->exit_cb((void *)sk);
    } else {
        modify_event(p_table->epfd, fd, (void *)sk, EPOLLIN);// | EPOLLET);
    }

WRITE_EXIT:
    return;
}

void frontend_socket_exit_cb(void *v)
{
    struct frontend_sk_node *sk = (struct frontend_sk_node *)v;
    struct frontend_work_thread_table *p_table = sk->p_my_table;

    if (sk->status == SOCKET_STATUS_DEL) {
        DBG_PRINTF(DBG_ERROR, "seq_id %u:%d front_listen_id:%u critical error alread del\n",
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

    frontend_move_node_to_list(sk, FRONTEND_SOCKET_TYPE_DEL);
    if (g_main_debug >= DBG_NORMAL) {
        char ip_str[30];
        uint32_t ip = htonl(sk->ip);
        DBG_PRINTF(DBG_WARNING, "exit seq_id %u:%d front_listen_id:%u connect from %s:%d, ttl: %d\n",
                sk->seq_id,
                sk->fd,
                sk->front_listen_id,
                inet_ntop(AF_INET, &ip, ip_str, sizeof(ip_str)),
                sk->port,
                time(NULL) - sk->last_active);
    }
}

void frontend_socket_del_cb(void *v)
{
    struct frontend_sk_node *sk = (struct frontend_sk_node *)v;
    struct frontend_work_thread_table *p_table = sk->p_my_table;

    if (sk->type != FRONTEND_SOCKET_TYPE_DEL) {
        DBG_PRINTF(DBG_ERROR, "user %u critical error %u:%d last_active: %d type: %hhu status: %hhu\n",
                sk->seq_id,
                sk->fd,
                sk->last_active,
                sk->type,
                sk->status);
    }

    struct list_table *p_list_table = &p_table->list[sk->type];

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

    free_frontend_socket_node(sk);
}

void frontend_event_connect(struct frontend_work_thread_table *p_table, struct frontend_sk_node *p_node)
{
    if (-1 == DHASH_INSERT(p_frontend_work_thread_table_array, &p_table->hash, p_node)) {
        DBG_PRINTF(DBG_ERROR, "new socket %u:%d exist!\n",
                p_node->seq_id,
                p_node->fd);
        frontend_sk_raw_del(p_node);
        return;
    }

    p_node->p_my_table      = p_table;
    p_node->backend_id      = 0;
    p_node->user_id         = 0;
    p_node->front_listen_id = 0;
    p_node->status          = SOCKET_STATUS_NEW;
    p_node->state           = HTTP_STATE_INIT;
    p_node->type            = FRONTEND_SOCKET_TYPE_READY;
    p_node->blocked         = 0;
    p_node->read_cb         = frontend_socket_read_cb;
    p_node->write_cb        = frontend_socket_write_cb;
    p_node->exit_cb         = frontend_socket_exit_cb;
    p_node->del_cb          = frontend_socket_del_cb;

    struct list_table *p_list_table = &p_table->list[FRONTEND_SOCKET_TYPE_READY];
    list_add_fe(&p_node->list_head, &p_list_table->list_head);
    p_list_table->num++;

    set_none_block(p_node->fd);
    add_event(p_table->epfd, p_node->fd, p_node, EPOLLIN);

    DBG_PRINTF(DBG_NORMAL, "new socket %d seq_id %u success\n",
            p_node->seq_id,
            p_node->fd);
}

void frontend_event_send(struct frontend_work_thread_table *p_table, struct notify_node *p_notify_node)
{
    struct frontend_sk_node *sk = DHASH_FIND(p_frontend_work_thread_table_array, &p_table->hash, &p_notify_node->dst_id);
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

void frontend_event_read_cb(void *v)
{
    struct frontend_sk_node *sk = (struct frontend_sk_node *)v;
    struct frontend_work_thread_table *p_my_table = sk->p_my_table;

    while(1) {
        uint64_t pipe_data;
        int nread = read(sk->fd, &pipe_data, sizeof(pipe_data));
        if (nread > 0) {
            if (nread != sizeof(pipe_data)) {
                DBG_PRINTF(DBG_ERROR, "pipe %d read error\n", sk->fd);
                continue;
            }

            struct notify_node *p_entry;
            while((p_entry = notify_table_get(&p_my_table->notify))) {
                switch(p_entry->type) {
                case PIPE_NOTIFY_TYPE_SEND:
                    frontend_event_send(p_my_table, p_entry);
                    break;

                case PIPE_NOTIFY_TYPE_FREE:
                    break;

                case PIPE_NOTIFY_TYPE_CONNECT:
                    frontend_event_connect(p_my_table, (struct frontend_sk_node *)p_entry->p_node);
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

void frontend_thread_event_init(struct frontend_work_thread_table *p_table)
{
    p_table->events = (struct epoll_event *)malloc(sizeof(struct epoll_event) * FRONTEND_THREAD_EPOLL_MAX_EVENTS);
    if (p_table->events == NULL)
        exit(EXIT_FAILURE);

    p_table->epfd = epoll_create(FRONTEND_THREAD_EPOLL_MAX_EVENTS);
    DBG_PRINTF(DBG_WARNING, "epfd %d\n", p_table->epfd);

    p_table->event_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (p_table->event_fd < 0) {
        DBG_PRINTF(DBG_WARNING, "create event_fd failed, ret %d!\n",
                p_table->event_fd);
        exit(EXIT_FAILURE);
    }

    struct frontend_sk_node *p_node = malloc_frontend_socket_node();
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
    p_node->type            = FRONTEND_SOCKET_TYPE_READY;
    p_node->read_cb         = frontend_event_read_cb;
    p_node->write_cb        = NULL;
    p_node->exit_cb         = NULL;
    p_node->del_cb          = NULL;

    set_none_block(p_node->fd);
    add_event(p_table->epfd, p_node->fd, p_node, EPOLLIN);

    DBG_PRINTF(DBG_WARNING, "add event_fd %d success!\n",
            p_table->event_fd);
}

void frontend_del_process(struct list_table *p_list_table)
{
    time_t now = time(NULL);
    int count = 0;
    struct list_head            *p_list = NULL;
    struct list_head            *p_next = NULL;
    list_for_each_safe(p_list, p_next, &p_list_table->list_head) {
        struct frontend_sk_node *p_entry = list_entry(p_list, struct frontend_sk_node, list_head);
        count++;
        p_entry->del_cb((void *)p_entry);
    }
    if (count)
        DBG_PRINTF(DBG_NORMAL, "del %d delay:%d\n", count, time(NULL) - now);
}

void *frontend_thread_socket_process(void *arg)
{
    struct frontend_work_thread_table *p_table = (struct frontend_work_thread_table *)arg;
    time_t last_time = time(NULL);

    prctl(PR_SET_NAME, p_table->table_name);

    DBG_PRINTF(DBG_WARNING, "%s enter timerstamp %d\n", p_table->table_name, last_time);

    while(g_main_running) {
        int nfds = epoll_wait(p_table->epfd, p_table->events, FRONTEND_THREAD_EPOLL_MAX_EVENTS, 1 * 1000);

        int i;
        for( i= 0; i < nfds; ++i) {
            struct frontend_sk_node *sk = (struct frontend_sk_node *)(p_table->events[i].data.ptr);

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

        frontend_del_process(&p_table->list[FRONTEND_SOCKET_TYPE_DEL]);
    }

    DBG_PRINTF(DBG_WARNING, "leave timestamp %d\n", time(NULL));

    exit(EXIT_SUCCESS);
}

int frontend_thread_pool_init()
{
    int i, res;

    p_frontend_work_thread_table_array = (struct frontend_work_thread_table *)malloc(sizeof(struct frontend_work_thread_table) * g_ctx.frontend_work_thread);
    if (p_frontend_work_thread_table_array == NULL)
        exit(EXIT_FAILURE);

    for (i = 0; i < g_ctx.frontend_work_thread; i++) {
        p_frontend_work_thread_table_array[i].index = i;
        pthread_mutex_init(&p_frontend_work_thread_table_array[i].mutex, NULL);
        sprintf(p_frontend_work_thread_table_array[i].table_name, "frontend_%d", i);

        int j;
        for (j = 0; j < FRONTEND_SOCKET_TYPE_MAX; j++) {
            INIT_LIST_HEAD(&p_frontend_work_thread_table_array[i].list[j].list_head);
            p_frontend_work_thread_table_array[i].list[j].num = 0;
        }

        DHASH_INIT(p_frontend_work_thread_table_array, &p_frontend_work_thread_table_array[i].hash, FRONTEND_THREAD_HASH_SIZE);
        notify_table_init(&p_frontend_work_thread_table_array[i].notify, "my_notify", 50000);

        frontend_thread_event_init(&p_frontend_work_thread_table_array[i]);

        res = pthread_create(&p_frontend_work_thread_table_array[i].thread_id, NULL, frontend_thread_socket_process, (void *)&p_frontend_work_thread_table_array[i]);

        if (res != 0) {
            perror("Thread creation failed!");
            exit(EXIT_FAILURE);
        }
    }
    return 0;
}

int frontend_init()
{
    frontend_socket_buff_table_init();
    frontend_listen_socket_buff_table_init();
    frontend_accept_init();
    frontend_thread_pool_init();
    return 0;
}

inline void frontend_event_notify(int event_fd)
{
    uint64_t notify = 1;
    if (write(event_fd, &notify, sizeof(notify)) < 0) {
        DBG_PRINTF(DBG_WARNING, "event_fd %d, write error!\n",
                event_fd);
    }
}

int frontend_notify_new_socket(struct frontend_sk_node *p_node)
{
    struct notify_node *p_notify_node = malloc_notify_node();
    if (p_notify_node == NULL) {
        return -1;
    }
    p_notify_node->type = PIPE_NOTIFY_TYPE_CONNECT;
    p_notify_node->p_node = p_node;

    int index = p_node->seq_id % g_ctx.frontend_work_thread;
    notify_table_put_head(&p_frontend_work_thread_table_array[index].notify, p_notify_node);
    frontend_event_notify(p_frontend_work_thread_table_array[index].event_fd);
    return 0;
}

int frontend_notify_send_data(struct notify_node *p_notify_node, uint32_t src_id, uint32_t dst_id)
{
    p_notify_node->type   = PIPE_NOTIFY_TYPE_SEND;
    p_notify_node->src_id = src_id;
    p_notify_node->dst_id = dst_id;

    int index = p_notify_node->dst_id % g_ctx.frontend_work_thread;
    notify_table_put_tail(&p_frontend_work_thread_table_array[index].notify, p_notify_node);
    frontend_event_notify(p_frontend_work_thread_table_array[index].event_fd);
    return 0;
}

void frontend_listen_socket_handle_accpet_cb(void *v)
{
    struct frontend_listen_sk_node *p_listen_node = (struct frontend_listen_sk_node *)v;
    struct sockaddr_in  client_addr;
    socklen_t           length          = sizeof(client_addr);
    int                 new_socket      = accept(p_listen_node->fd, (struct sockaddr*)&client_addr, &length);

    if (new_socket < 0) {
        DBG_PRINTF(DBG_ERROR, "Accept Failed! error no: %d, error msg: %s\n",
                errno,
                strerror(errno));
        return;
    }

    struct frontend_sk_node *p_node = malloc_frontend_socket_node();
    if (p_node == NULL) {
        char ip_str[32];
        DBG_PRINTF(DBG_ERROR, "new socket %d connect from %s:%hu failed\n",
                new_socket,
                inet_ntop(AF_INET, &client_addr.sin_addr.s_addr, ip_str, sizeof(ip_str)),
                client_addr.sin_port);
        close(new_socket);
        return;
    }

    uint32_t ip = ntohl(client_addr.sin_addr.s_addr);

    p_node->id_hash_node.prev = p_node->id_hash_node.next = NULL;
    p_node->fd              = new_socket;
    p_node->ip              = ip;
    p_node->port            = ntohs(client_addr.sin_port);
    p_node->my_port         = p_listen_node->my_port;
    p_node->p_recv_node     = NULL;
    p_node->last_active     = time(NULL);
    p_node->blocked         = 0;

    INIT_LIST_HEAD(&p_node->send_list);

    if (frontend_notify_new_socket(p_node) == -1) {
        close(new_socket);
        free_frontend_socket_node(p_node);

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

void *frontend_accept_process(void *arg)
{
    struct frontend_accept_socket_table *p_table = &g_frontend_accept_socket_table;

    prctl(PR_SET_NAME, __FUNCTION__);

    DBG_PRINTF(DBG_WARNING, "enter timerstamp %d\n", time(NULL));

    while(g_main_running) {
        int nfds = epoll_wait(p_table->epfd, p_table->events, FRONTEND_ACCEPT_EPOLL_MAX_EVENTS, -1);

        int i;
        for (i= 0; i < nfds; ++i) {
            struct frontend_listen_sk_node *sk = (struct frontend_listen_sk_node *)(p_table->events[i].data.ptr);
            if (p_table->events[i].events & EPOLLIN) {
                sk->accept_cb(sk);
            } else {
                DBG_PRINTF(DBG_ERROR, "unknown event: %d\n",
                        p_table->events[i].events);
            }
        }
    }

    DBG_PRINTF(DBG_WARNING, "leave timestamp %d\n", time(NULL));

    exit(EXIT_SUCCESS);
}
