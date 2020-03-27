#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#include <stddef.h>
#include <limits.h>

#include <sys/msg.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <pthread.h>
#include <sys/prctl.h>
#include <sys/select.h>
#include <netinet/tcp.h>
#include <openssl/md5.h>
#include <json-c/json.h>
#include <sys/eventfd.h>
#include <sys/time.h>

#include "dc_mysql.h"
#include "log.h"
#include "misc.h"
#include "buff.h"
#include "user.h"
#include "heaptimer.h"


extern int g_main_running;
extern int g_main_debug;

const ngx_str_t g_const_control_pattern_json = ngx_string("json");

const ngx_str_t g_const_control_attr_user_name = ngx_string("user_name");
const ngx_str_t g_const_control_attr_password = ngx_string("password");
const ngx_str_t g_const_control_attr_domain = ngx_string("domain");
const ngx_str_t g_const_control_attr_prefix = ngx_string("prefix");
const ngx_str_t g_const_control_attr_total_flow = ngx_string("total_flow");
const ngx_str_t g_const_control_attr_used_flow = ngx_string("used_flow");
const ngx_str_t g_const_control_attr_end_time = ngx_string("end_time");

const ngx_str_t g_const_control_attr_pattern = ngx_string("pattern");
const ngx_str_t g_const_control_attr_fmt    = ngx_string("fmt");
const ngx_str_t g_const_control_attr_number = ngx_string("number");
const ngx_str_t g_const_control_attr_ip = ngx_string("ip");

struct user_interface_block {
    ngx_str_t               func_name;
    enum user_req_type      type;
    int                     (*p_kv_func)(ngx_str_t *p_key_value, struct user_interface_parse_block *p_user_block);
};

int user_interface_parse_debug_kv(ngx_str_t *p_key_value, struct user_interface_parse_block *p_user_block);
int user_interface_parse_account_kv(ngx_str_t *p_key_value, struct user_interface_parse_block *p_user_block);
int user_interface_parse_query_ip_kv(ngx_str_t *p_key_value, struct user_interface_parse_block *p_user_block);

const struct user_interface_block g_user_interface[] = {
    {ngx_string("debug"), USER_REQ_TYPE_DEBUG, user_interface_parse_debug_kv},
    {ngx_string("add_account"), USER_REQ_TYPE_ADD_ACCOUNT, user_interface_parse_account_kv},
    {ngx_string("mdf_account"), USER_REQ_TYPE_MDF_ACCOUNT, user_interface_parse_account_kv},
    {ngx_string("del_account"), USER_REQ_TYPE_DEL_ACCOUNT, user_interface_parse_account_kv},
    {ngx_string("query_account"), USER_REQ_TYPE_QUERY_ACCOUNT, user_interface_parse_account_kv},
    {ngx_string("query_ip"), USER_REQ_TYPE_QUERY_IP, user_interface_parse_query_ip_kv},
};

#if 1

struct debug_cb {
    ngx_str_t   func_name;
    void        (*cb)(int argc, void *argv);
};

#define DBG_CB_INIT(name) {\
    .func_name = ngx_string(#name),\
    .cb        = name\
}

void set_g_main_debug(int argc, void *argv);

struct debug_cb g_debug_cb[] = {
    DBG_CB_INIT(display_g_user_table),
    DBG_CB_INIT(display_g_user_buff_table),
    DBG_CB_INIT(set_g_main_debug)
};

int user_debug(struct user_interface_parse_block *p_user_interface_parse_block)
{
    ngx_str_t *p_func = NULL;
    ngx_str_t *p_arg = NULL;
    char func_name[300];
    char arg_str[300];
    struct user_debug_block *p_data = &p_user_interface_parse_block->req.debug;

    if (p_data->param_num < 1)
        return USER_CODE_TYPE_URL_ERR;
    p_func = &p_data->param[0];
    p_arg = &p_data->param[1];

    DBG_PRINTF(DBG_ERROR, "func_name: [%s] param_num: [%d] arg: [%s]\n",
            ngx_print(func_name, 300, p_func),
            p_data->param_num,
            ngx_print(arg_str, 300, p_arg));

    int i;
    for (i = 0; i < (sizeof(g_debug_cb) / sizeof(struct debug_cb)); i++) {
        struct debug_cb *p_debug_cb = &g_debug_cb[i];

        if (0 == ngx_cmp(p_func, &p_debug_cb->func_name)) {
            p_debug_cb->cb(p_data->param_num - 1, (void *)p_arg);
            return USER_CODE_TYPE_SUCCESS;
        }
    }

    return USER_CODE_TYPE_URL_ERR;
}

#endif

const char *g_user_code_type_str[USER_CODE_TYPE_MAX] = {
    "成功",
    "URL错误",
    "认证失败",
    "帐号已过期",
    "配额已用完，请充值",
    "参数错误",
    "用户已存在",
    "用户不存在",
    "用户已删除",
    "内部错误",
};


#if 1

struct buff_table g_user_buf_table;

void user_buf_table_init()
{
    buff_table_init(&g_user_buf_table, USER_MAX_NUM, sizeof(struct user_node), "g_user_buf_table");
}

inline struct user_node *malloc_user_node()
{
    return (struct user_node *)buff_table_malloc_node(&g_user_buf_table);
}

inline void free_user_node(struct user_node *p_node)
{
    buff_table_free_node(&g_user_buf_table, &p_node->list_head);
}


void display_g_user_buff_table()
{
    display_buff_table(&g_user_buf_table);
}

#endif

#if 1
struct buff_table g_user_resp_buf_table;

void resp_buf_table_init()
{
    buff_table_init(&g_user_resp_buf_table, USER_SOCKET_BUF_MAX_NUM, sizeof(struct user_resp_buf_node), "g_user_resp_buf_table");
}

inline struct user_resp_buf_node *malloc_user_resp_buf_node()
{
    return (struct user_resp_buf_node *)buff_table_malloc_node(&g_user_resp_buf_table);
}

inline void free_user_resp_buf_node(struct user_resp_buf_node *p_node)
{
    buff_table_free_node(&g_user_resp_buf_table, &p_node->list_head);
}

void display_g_user_resp_buff_table()
{
    display_buff_table(&g_user_resp_buf_table);
}

#endif

#if 2

struct user_table g_user_table;

DHASH_GENERATE(g_user_table, user_node, hash_node, ngx_user_name, ngx_str_t, ngx_hash, ngx_cmp);

inline void user_table_lock()
{
    pthread_mutex_lock(&g_user_table.mutex);
}

inline void user_table_unlock()
{
    pthread_mutex_unlock(&g_user_table.mutex);
}

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
        )
{
    struct user_table *p_table = &g_user_table;
    int ret = SUCCESS;
    int name_len = strlen(user_name);
    int password_len = strlen(password);
    int domain_len = strlen(domain);

    user_table_lock();

    if (name_len <= 0
            || name_len > USER_NAME_MAX_LEN
            || password_len > PASSWORD_MAX_LEN
            || domain_len > DOMAIN_MAX_LEN
            || start_time == TIME_INVALID_VALUE
            || end_time == TIME_INVALID_VALUE
            || total_flow == UINT64_INVALID_VALUE) {
        ret = FAIL;
        *code = USER_CODE_TYPE_PARAM_ERR;
        DBG_PRINTF(DBG_WARNING, "param error, user_name len %d, start_time %d, end_time %d, total_flow %d\n", 
                name_len,
                start_time,
                end_time,
                total_flow);
        goto USER_ADD_EXIT;
    }

    ngx_str_t ngx_user_name = {
        .data = (uint8_t *)user_name,
        .len = name_len
    };

    struct user_node *p_user_block = DHASH_FIND(g_user_table, &p_table->hash, &ngx_user_name);

    /* add new */
    if (p_user_block) {
        ret = FAIL;
        *code = USER_CODE_TYPE_USER_EXIST;
        goto USER_ADD_EXIT;
    }

    p_user_block = malloc_user_node();
    if (NULL == p_user_block) {
        DBG_PRINTF(DBG_ERROR, "add new user[%s] failed, malloc user node failed\n", user_name);
        ret = FAIL;
        *code = USER_CODE_TYPE_INNER_ERR;
        goto USER_ADD_EXIT;
    }

    memset(p_user_block, 0, sizeof(struct user_node));
    INIT_LIST_HEAD(&p_user_block->list_head);
    INIT_LIST_HEAD(&p_user_block->hash_node);

    //add from interface
    if (user_id == 0) {
        p_table->current_max_user_id++;
        p_user_block->user_id = p_table->current_max_user_id;
    } else {
        if (user_id > p_table->current_max_user_id)
            p_table->current_max_user_id = user_id;
        p_user_block->user_id = user_id;
    }

    memcpy(p_user_block->user_name, user_name, name_len);
    p_user_block->user_name[name_len] = 0;
    p_user_block->ngx_user_name.data = (uint8_t *)p_user_block->user_name;
    p_user_block->ngx_user_name.len = name_len;

    memcpy(p_user_block->password, password, password_len);
    p_user_block->password[password_len] = 0;

    memcpy(p_user_block->domain, domain, domain_len);
    p_user_block->domain[domain_len] = 0;


    p_user_block->time = time;
    p_user_block->start_time = start_time;
    p_user_block->end_time = end_time;
    p_user_block->del_flag = del_flag;
    p_user_block->total_flow = total_flow;
    if (used_flow != UINT64_INVALID_VALUE)
        p_user_block->used_flow = used_flow;

    if (-1 == DHASH_INSERT(g_user_table, &p_table->hash, p_user_block)) {
        DBG_PRINTF(DBG_ERROR, "add new user[%s], failed add hash failed\n", p_user_block->user_name);
        free_user_node(p_user_block);
        ret = FAIL;
        *code = USER_CODE_TYPE_INNER_ERR;
        goto USER_ADD_EXIT;
    }

    p_user_block->store = false;

    list_add_fe(&p_user_block->list_head, &p_table->list.list_head);
    p_table->list.num++;

    DBG_PRINTF(DBG_ERROR, "add new user[%s] success\n", p_user_block->user_name);

    //add from interface
    if (user_id == 0) {
        dc_mysql_store_account(p_user_block);
    }

USER_ADD_EXIT:
    user_table_unlock();

    return ret;
}

int user_mdf_account_in_table(
        enum user_code_type *code,
        ngx_str_t *p_ngx_user_name,
        ngx_str_t *p_ngx_password,
        ngx_str_t *p_ngx_domain,
        time_t end_time,
        uint64_t total_flow,
        uint64_t used_flow
        )
{
    struct user_table *p_table = &g_user_table;
    int ret = SUCCESS;

    user_table_lock();

    struct user_node *p_user_block = DHASH_FIND(g_user_table, &p_table->hash, p_ngx_user_name);

    if (NULL == p_user_block) {
        char user_name[USER_NAME_MAX_LEN + 1];
        DBG_PRINTF(DBG_ERROR, "user:[%s] not found\n", ngx_print(user_name, USER_NAME_MAX_LEN, p_ngx_user_name));

        ret = FAIL;
        *code = USER_CODE_TYPE_USER_NOT_FOUND;
        goto USER_MDF_EXIT;
    }

    if (p_user_block->del_flag == 1) {
        DBG_PRINTF(DBG_ERROR, "user:[%s] del already\n", p_user_block->user_name);
        ret = FAIL;
        *code = USER_CODE_TYPE_USER_ALREADY_DEL;
        goto USER_MDF_EXIT;
    }

    p_user_block->time      = time(NULL);
    //to mdf end_time
    if (end_time != 0)
        p_user_block->end_time  = end_time;

    if (p_ngx_password->data != NULL) {
        memcpy(p_user_block->password, p_ngx_password->data, p_ngx_password->len);
        p_user_block->password[p_ngx_password->len] = 0;
    }

    if (p_ngx_domain->data != NULL) {
        memcpy(p_user_block->domain, p_ngx_domain->data, p_ngx_domain->len);
        p_user_block->domain[p_ngx_domain->len] = 0;
    }

    if (total_flow != UINT64_INVALID_VALUE)
        p_user_block->total_flow = total_flow;

    if (used_flow != UINT64_INVALID_VALUE)
        p_user_block->used_flow = used_flow;

    dc_mysql_store_account(p_user_block);

    DBG_PRINTF(DBG_ERROR, "mdf user:[%u][%s] success\n",
            p_user_block->user_id,
            p_user_block->user_name);

USER_MDF_EXIT:
    user_table_unlock();

    return ret;
}


int user_del_account_in_table(
        enum user_code_type *code,
        ngx_str_t *p_ngx_user_name
        )
{
    struct user_table *p_table = &g_user_table;
    int ret = SUCCESS;

    user_table_lock();

    struct user_node *p_user_block = DHASH_FIND(g_user_table, &p_table->hash, p_ngx_user_name);

    if (NULL == p_user_block) {
        char user_name[USER_NAME_MAX_LEN + 1];
        DBG_PRINTF(DBG_ERROR, "user:[%s] not found\n", ngx_print(user_name, USER_NAME_MAX_LEN, p_ngx_user_name));

        ret = FAIL;
        *code = USER_CODE_TYPE_USER_NOT_FOUND;
        goto USER_DEL_EXIT;
    }

    if (p_user_block->del_flag == 1) {
        DBG_PRINTF(DBG_ERROR, "user:[%s] del already\n", p_user_block->user_name);
        ret = FAIL;
        *code = USER_CODE_TYPE_USER_ALREADY_DEL;
        goto USER_DEL_EXIT;
    }

    p_user_block->del_flag  = 1;
    p_user_block->time      = time(NULL);

    dc_mysql_store_account(p_user_block);

    DBG_PRINTF(DBG_ERROR, "del user:[%u][%s] success\n",
            p_user_block->user_id,
            p_user_block->user_name);

USER_DEL_EXIT:
    user_table_unlock();

    return ret;
}

int user_make_md5(uint8_t *md5, char *password, uint32_t salt)
{
#define MD5_STR_BUF_LEN   (PASSWORD_MAX_LEN + 20)
    uint8_t md5_str_buf[MD5_STR_BUF_LEN + 1] = {0};
    size_t  md5_str_buf_len;

    md5_str_buf_len = snprintf((char *)md5_str_buf, MD5_STR_BUF_LEN, "%s%u", password, salt);
    if (NULL == MD5(md5_str_buf, md5_str_buf_len, md5)) {
        DBG_PRINTF(DBG_ERROR, "md5 error! str: %s, len: %d\n",
                md5_str_buf,
                md5_str_buf_len);
        return FAIL;
    }
    return SUCCESS;
}

int user_auth_and_get_domain(struct domain_node *p_domain_node, char *user_name, char *md5, uint32_t salt)
{
    struct user_table *p_table = &g_user_table;
    int ret = SUCCESS;
    ngx_str_t ngx_user_name = {
        .data = (uint8_t *)user_name,
        .len = strlen(user_name)
    };

    user_table_lock();

    struct user_node *p_user_block = DHASH_FIND(g_user_table, &p_table->hash, &ngx_user_name);

    if (NULL == p_user_block) {
        DBG_PRINTF(DBG_ERROR, "user:[%s] not found\n", user_name);
        ret = FAIL;
        goto EXIT;
    }

    if (p_user_block->del_flag == 1) {
        DBG_PRINTF(DBG_ERROR, "user:[%s] del already\n", p_user_block->user_name);
        ret = FAIL;
        goto EXIT;
    }

    uint8_t check_md5[32] = {0};
    ret = user_make_md5(check_md5, p_user_block->password, salt);
    if (ret == FAIL) {
        goto EXIT;
    }

    if (memcmp(md5, check_md5, 32) == 0) {
        strncpy(p_domain_node->domain, p_user_block->domain, DOMAIN_MAX_LEN);
        p_domain_node->domain[DOMAIN_MAX_LEN] = 0;
        p_domain_node->ngx_domain.data = (uint8_t *)p_domain_node->domain;
        p_domain_node->ngx_domain.len = strlen(p_domain_node->domain);

        p_domain_node->user_id = p_user_block->user_id;
    } else {
        DBG_PRINTF(DBG_ERROR, "user:[%s] md5 unmatch\n", p_user_block->user_name);
        ret = FAIL;
        goto EXIT;
    }


EXIT:
    user_table_unlock();
    return ret;
}

#endif

#if 2
void set_g_main_debug(int argc, void *argv)
{
    if (argc < 1) 
        return;

    ngx_str_t *p_arg = &((ngx_str_t *)argv)[0];
    if (p_arg->data == NULL
            || p_arg->len <= 0)
        return;

    p_arg->data[p_arg->len] = 0;
    int value = atoi((char *)p_arg->data);
    DBG_PRINTF(DBG_WARNING, "set g_main_debug: %d to %d\n",
            g_main_debug, value);
    g_main_debug = value;
}

void display_g_user_table()
{
    struct user_table           *p_table = &g_user_table;
    struct list_head            *p_list = NULL;
    struct list_table           *p_list_table = &p_table->list;

    user_table_lock();

    DBG_RAW_PRINTF("\n%s, %d, user_num: %hu, display start\n", __FUNCTION__, __LINE__, p_list_table->num);
    list_for_each(p_list, &p_list_table->list_head) {
        struct user_node *p_entry = list_entry(p_list, struct user_node, list_head);

        DBG_RAW_PRINTF(" user_id:%u,user_name:%s,password:%s,domain:%s,start_time:%u,end_time:%u,del_flag:%hhu,total_flow:%lu,used_flow:%lu\n",
                p_entry->user_id,
                p_entry->user_name,
                p_entry->password,
                p_entry->domain,
                p_entry->start_time,
                p_entry->end_time,
                p_entry->del_flag,
                p_entry->total_flow,
                p_entry->used_flow
                );
    }

    user_table_unlock();

    DBG_RAW_PRINTF("\n%s, %d, display end\n", __FUNCTION__, __LINE__);
}


void user_ip_old_process(bool new_day)
{
    struct user_table           *p_table = &g_user_table;
    struct list_head            *p_list = NULL;
    struct list_table           *p_list_table = &p_table->list;

    user_table_lock();

    list_for_each(p_list, &p_list_table->list_head) {
        struct user_node *p_entry = list_entry(p_list, struct user_node, list_head);

        if (new_day) {
        }

        if (p_entry->store) {
            p_entry->store = false;
            dc_mysql_store_account(p_entry);
        }
    }

    user_table_unlock();
}

void user_table_init()
{
    user_buf_table_init();
    user_socket_init();

    struct user_table *p_table = &g_user_table;

    pthread_mutex_init(&p_table->mutex, NULL);
    strncpy(p_table->table_name, "g_user_table", TABLE_NAME_LEN);
    p_table->current_max_user_id = 0;

    INIT_LIST_HEAD(&p_table->list.list_head);
    p_table->list.num = 0;

    DHASH_INIT(g_user_table, &p_table->hash, USER_MAX_NUM);
}

#endif

#if 3

struct buff_table g_user_socket_buf_table;

void user_socket_buf_table_init()
{
    buff_table_init(&g_user_socket_buf_table, USER_SOCKET_BUF_MAX_NUM, sizeof(struct user_sk_node), "g_user_socket_buf_table");
}

inline struct user_sk_node *malloc_user_socket_node()
{
    return (struct user_sk_node *)buff_table_malloc_node(&g_user_socket_buf_table);
}

inline void free_user_socket_node(struct user_sk_node *p_node)
{
    buff_table_free_node(&g_user_socket_buf_table, &p_node->list_head);
}

void display_g_user_socket_buff_table()
{
    display_buff_table(&g_user_socket_buf_table);
}

#endif

#if 3
struct user_socket_table g_user_socket_table;

void user_move_node_to_list(struct user_sk_node *sk, int type)
{
    DBG_PRINTF(DBG_NORMAL, "user %u list move %d --> %d\n",
            sk->seq_id,
            sk->type,
            type);

    struct user_socket_table *p_table = sk->p_table;
    list_move(&sk->list_head, &p_table->list_head[type].list_head);
    if (sk->type != type)
    {
        p_table->list_head[sk->type].num--;
        p_table->list_head[type].num++;
        sk->type = type;
    }
}

int user_interface_parse_account_kv(ngx_str_t *p_key_value, struct user_interface_parse_block *p_user_block)
{
    struct user_account_block *p_data = &p_user_block->req.account;
    ngx_str_t item;
    ngx_str_t key, value;
    bool done = false;

    memset(p_data, 0, sizeof(struct user_account_block));
    p_data->end_time = TIME_INVALID_VALUE;
    p_data->total_flow = UINT64_INVALID_VALUE;
    p_data->used_flow = UINT64_INVALID_VALUE;

    while (!done) {
        if (0 != ngx_split(p_key_value, '&', &item, p_key_value)) {
            item = *p_key_value;
            done = true;
        }
        if (-1 == ngx_split(&item, '=', &key, &value))
            return -1;

        value.data[value.len] = 0;
        if (0 == ngx_cmp(&key, &g_const_control_attr_pattern)) {
            p_data->pattern = value;
        } else if (0 == ngx_cmp(&key, &g_const_control_attr_user_name)) {
            p_data->ngx_user_name = value;
        } else if (0 == ngx_cmp(&key, &g_const_control_attr_password)) {
            p_data->ngx_password = value;
        } else if (0 == ngx_cmp(&key, &g_const_control_attr_domain)) {
            p_data->ngx_domain = value;
        } else if (0 == ngx_cmp(&key, &g_const_control_attr_prefix)) {
        } else if (0 == ngx_cmp(&key, &g_const_control_attr_prefix)) {
            p_data->prefix = value;
        } else if (0 == ngx_cmp(&key, &g_const_control_attr_end_time)) {
            if (value.len < 7 || value.len > 15) {
                DBG_PRINTF(DBG_WARNING, "len error %d\n",
                        value.len);
                return -1;
            }
            p_data->end_time = str_to_u32_base10((char *)value.data);
        } else if (0 == ngx_cmp(&key, &g_const_control_attr_total_flow)) {
            if (value.len < 1) {
                DBG_PRINTF(DBG_WARNING, "len error %d\n",
                        value.len);
                return -1;
            }
            p_data->total_flow = str_to_u64_base10((char *)value.data);
        } else if (0 == ngx_cmp(&key, &g_const_control_attr_used_flow)) {
            if (value.len < 1) {
                DBG_PRINTF(DBG_WARNING, "len error %d\n",
                        value.len);
                return -1;
            }
            p_data->used_flow = str_to_u64_base10((char *)value.data);
        } else {
            return -1;
        }
    }
    return 0;
}

int user_interface_parse_query_ip_kv(ngx_str_t *p_key_value, struct user_interface_parse_block *p_user_block)
{
    struct user_query_ip_block *p_data = &p_user_block->req.query;
    ngx_str_t item;
    ngx_str_t key, value;
    bool done = false;

    memset(p_data, 0, sizeof(struct user_query_ip_block));

    while (!done) {
        if (0 != ngx_split(p_key_value, '&', &item, p_key_value)) {
            item = *p_key_value;
            done = true;
        }
        if (-1 == ngx_split(&item, '=', &key, &value))
            return -1;

        value.data[value.len] = 0;
        if (0 == ngx_cmp(&key, &g_const_control_attr_pattern)) {
            p_data->pattern = value;
        } else if (0 == ngx_cmp(&key, &g_const_control_attr_user_name)) {
            p_data->user_name = value;
        } else if (0 == ngx_cmp(&key, &g_const_control_attr_ip)) {
            if (value.len < 7 || value.len > 15) {
                DBG_PRINTF(DBG_WARNING, "len error %d\n",
                        value.len);
                return -1;
            }

            struct in_addr ip_addr;
            inet_aton((char *)value.data, &ip_addr);
            p_data->ip = ntohl(ip_addr.s_addr);
        } else {
            return -1;
        }
    }
    return 0;
}

int user_interface_parse_debug_kv(ngx_str_t *p_key_value, struct user_interface_parse_block *p_user_block)
{
    struct user_debug_block *p_data = &p_user_block->req.debug;
    ngx_str_t item;

    p_data->param_num = 0;

    for (;p_data->param_num < 5;p_data->param_num++) {
        if (0 == ngx_split(p_key_value, '&', &item, p_key_value)) {
            p_data->param[p_data->param_num] = item;
        } else {
            p_data->param[p_data->param_num] = *p_key_value;
            p_data->param_num++;
            break;
        }
    }

    return 0;
}

void user_data_parse(struct user_sk_node *sk, struct user_interface_parse_block *p_parse_block)
{
    uint8_t *p_buf = sk->p_recv_node->buf + sk->p_recv_node->pos;
    uint16_t n_recv = sk->p_recv_node->end - sk->p_recv_node->pos;

    p_parse_block->type = USER_REQ_TYPE_NEED_MORE;

    DBG_DUMP_HEX(DBG_NORMAL, p_buf, n_recv);

    if (n_recv < 4)
        return;

    uint8_t *p_end = p_buf + n_recv - 4;
    if (!(p_end[0] == 0x0d
                && p_end[1] == 0x0a
                && p_end[2] == 0x0d
                && p_end[3] == 0x0a)) {
        if (n_recv > 1000) {
            p_parse_block->type = USER_REQ_TYPE_UNKNOWN;
            p_parse_block->code = USER_CODE_TYPE_INNER_ERR;
            DBG_PRINTF(DBG_WARNING, "seq_id %u unknown http header n_recv %hu!\n",
                    sk->seq_id,
                    n_recv);
            return;
        }
        return;
    }


    if (!ngx_str4cmp(p_buf, 'G', 'E', 'T', ' ')) {
        goto INTERFACE_PARSE_ERR_EXIT;
    }

    ngx_str_t ngx_data;
    ngx_data.data = p_buf + 5;
    ngx_data.len = p_end - ngx_data.data;

    ngx_str_t url;
    ngx_str_t rest;
    if (-1 == ngx_split(&ngx_data, ' ', &url, &rest)) {
        goto INTERFACE_PARSE_ERR_EXIT;
    }

    ngx_str_t func;
    if (-1 == ngx_split(&url, '?', &func, &rest)) {
        goto INTERFACE_PARSE_ERR_EXIT;
    }

    int i;
    for (i = 0; i < (sizeof(g_user_interface) / sizeof(struct user_interface_block)); i++) {
        const struct user_interface_block *p_block = &g_user_interface[i];

        if (0 == ngx_cmp(&func, &p_block->func_name)) {
            p_parse_block->type = p_block->type;
            int ret = p_block->p_kv_func(&rest, p_parse_block);
            if (ret != 0) {
                goto INTERFACE_PARSE_ERR_EXIT;
            }
            return;
        }
    }

    char func_str[200];
    DBG_PRINTF(DBG_WARNING, "seq_id %u unknown http header n_recv %hu, func %s!\n",
            sk->seq_id,
            n_recv,
            ngx_print(func_str, 199, &func));

INTERFACE_PARSE_ERR_EXIT:
    p_parse_block->type = USER_REQ_TYPE_UNKNOWN;
    p_parse_block->code = USER_CODE_TYPE_PARAM_ERR;
    DBG_PRINTF(DBG_WARNING, "seq_id %u unknown http header n_recv %hu!\n",
            sk->seq_id,
            n_recv);
    DBG_DUMP_HEX(DBG_NORMAL, p_buf, n_recv);
    return;
}

#define LOCAL_CHECK() {\
    if (sk->ip != 0x7f000001) {\
        p_user_interface_parse_block->code = USER_CODE_TYPE_INNER_ERR;\
        char ip_str[16];\
        uint32_t ip = htonl(sk->ip);    \
        DBG_PRINTF(DBG_WARNING, "invalid ip %s\n",\
                inet_ntop(AF_INET, &ip, ip_str, sizeof(ip_str)));\
        return;\
    }\
}

int user_create_user_name(ngx_str_t prefix, char *name)
{
    struct user_table *p_table = &g_user_table;
    uint32_t rand_num;
    int ret = SUCCESS;
    uint8_t md5[32];
    int i;
    int len;

    srand(time(NULL));
    rand_num = rand();

    user_table_lock();

    while(1) {
        if (NULL == MD5((unsigned char *)&rand_num, sizeof(uint32_t), md5)) {
            DBG_PRINTF(DBG_ERROR, "md5 error! str: %u\n", rand_num);
            ret = FAIL;
            break;
        }


        len = sprintf(name, "%s_",
                prefix.len ? (char *)prefix.data : "sys");
        for (i = 0; i < 6; i ++)
            len += sprintf(name + len, "%02x", md5[i]);

        ngx_str_t user_name = {
            .data = (uint8_t *)name,
            .len = len
        };
        if (NULL == DHASH_FIND(g_user_table, &p_table->hash, &user_name)) {
            break;
        }

        rand_num += rand();
    }
    user_table_unlock();

    return ret;
}


/*
 * 使用接口添加帐户
 */
void user_add_account(struct user_sk_node *sk, struct user_interface_parse_block *p_user_interface_parse_block)
{
    p_user_interface_parse_block->code = USER_CODE_TYPE_SUCCESS;
    struct user_account_block *p_req = &p_user_interface_parse_block->req.account;

    LOCAL_CHECK();

    time_t now = time(NULL);
    if (p_req->end_time < now) {
        p_user_interface_parse_block->code = USER_CODE_TYPE_PARAM_ERR;
        DBG_PRINTF(DBG_WARNING, "end_time %d less than now_time %d\n", p_req->end_time, now);
        return;
    }

    if (p_req->prefix.data) {
        if (FAIL == user_create_user_name(p_req->prefix, p_req->user_name)) {
            p_user_interface_parse_block->code = USER_CODE_TYPE_INNER_ERR;
            return;
        }
    } else {
        if (p_req->ngx_user_name.len < 1 || p_req->ngx_user_name.len >= USER_NAME_MAX_LEN) {
            p_user_interface_parse_block->code = USER_CODE_TYPE_PARAM_ERR;
            DBG_PRINTF(DBG_WARNING, "user_name len %d illegal, should between 1 and %d\n", p_req->ngx_user_name.len, USER_NAME_MAX_LEN);
            return;
        }
        memcpy(p_req->user_name, p_req->ngx_user_name.data, p_req->ngx_user_name.len);
        p_req->user_name[p_req->ngx_user_name.len] = 0;
    }

    if (p_req->ngx_password.len < 1 || p_req->ngx_password.len >= PASSWORD_MAX_LEN
            || p_req->ngx_domain.len < 1 || p_req->ngx_domain.len >= DOMAIN_MAX_LEN) {
        p_user_interface_parse_block->code = USER_CODE_TYPE_PARAM_ERR;
        DBG_PRINTF(DBG_WARNING, "password len %d illegal, should between 1 and %d\n", p_req->ngx_password.len, PASSWORD_MAX_LEN);
        DBG_PRINTF(DBG_WARNING, "domain len %d illegal, should between 1 and %d\n", p_req->ngx_domain.len, DOMAIN_MAX_LEN);
        return;
    }
    memcpy(p_req->password, p_req->ngx_password.data, p_req->ngx_password.len);
    p_req->password[p_req->ngx_password.len] = 0;
    memcpy(p_req->domain, p_req->ngx_domain.data, p_req->ngx_domain.len);
    p_req->domain[p_req->ngx_domain.len] = 0;

    DBG_PRINTF(DBG_WARNING, "name %s\n", p_req->user_name);

    int ret = user_add_account_to_table(
            &p_user_interface_parse_block->code,
            0,
            p_req->user_name,
            p_req->password,
            p_req->domain,
            now,
            p_req->end_time,
            0,
            p_req->total_flow,
            p_req->used_flow,
            now);

    if (ret == SUCCESS) {
        struct user_account_block *p_resp = &p_user_interface_parse_block->resp.account;

        strncpy(p_resp->user_name, p_req->user_name, USER_NAME_MAX_LEN);
        p_resp->end_time = p_req->end_time;
        p_resp->total_flow = p_req->total_flow;

        p_user_interface_parse_block->code = USER_CODE_TYPE_SUCCESS;
    }
}

void user_mdf_account(struct user_sk_node *sk, struct user_interface_parse_block *p_user_interface_parse_block)
{
    p_user_interface_parse_block->code = USER_CODE_TYPE_SUCCESS;
    struct user_account_block *p_req = &p_user_interface_parse_block->req.account;

    LOCAL_CHECK();

    if (p_req->ngx_user_name.len < 1 || p_req->ngx_user_name.len >= USER_NAME_MAX_LEN) {
        p_user_interface_parse_block->code = USER_CODE_TYPE_PARAM_ERR;
        return;
    }

    int ret = user_mdf_account_in_table(
            &p_user_interface_parse_block->code,
            &p_req->ngx_user_name,
            &p_req->ngx_password,
            &p_req->ngx_domain,
            p_req->end_time,
            p_req->total_flow,
            p_req->used_flow);

    if (ret == SUCCESS) {
        struct user_account_block *p_resp = &p_user_interface_parse_block->resp.account;

        strncpy(p_resp->user_name, p_req->user_name, USER_NAME_MAX_LEN);
        p_resp->end_time = p_req->end_time;
        p_resp->total_flow = p_req->total_flow;

        p_user_interface_parse_block->code = USER_CODE_TYPE_SUCCESS;
    }
}

void user_del_account(struct user_sk_node *sk, struct user_interface_parse_block *p_user_interface_parse_block)
{
    p_user_interface_parse_block->code = USER_CODE_TYPE_SUCCESS;
    struct user_account_block *p_req = &p_user_interface_parse_block->req.account;

    LOCAL_CHECK();

    if (p_req->ngx_user_name.len < 1 || p_req->ngx_user_name.len >= USER_NAME_MAX_LEN) {
        p_user_interface_parse_block->code = USER_CODE_TYPE_PARAM_ERR;
        return;
    }

    int ret = user_del_account_in_table(
            &p_user_interface_parse_block->code,
            &p_req->ngx_user_name);

    if (ret == SUCCESS) {
        struct user_account_block *p_resp = &p_user_interface_parse_block->resp.account;

        strncpy(p_resp->user_name, p_req->user_name, USER_NAME_MAX_LEN);

        p_user_interface_parse_block->code = USER_CODE_TYPE_SUCCESS;
    }
}

void user_query_account(struct user_sk_node *sk, struct user_interface_parse_block *p_user_interface_parse_block)
{
    p_user_interface_parse_block->code = USER_CODE_TYPE_SUCCESS;
    struct user_account_block *p_req = &p_user_interface_parse_block->req.account;

    if (p_req->ngx_user_name.len < 1 || p_req->ngx_user_name.len >= USER_NAME_MAX_LEN) {
        p_user_interface_parse_block->code = USER_CODE_TYPE_PARAM_ERR;
        return;
    }

    struct user_table *p_table = &g_user_table;

    user_table_lock();

    struct user_node *p_user_block = DHASH_FIND(g_user_table, &p_table->hash, &p_req->ngx_user_name);
    char user_name[USER_NAME_MAX_LEN + 1];

    if (NULL == p_user_block) {
        DBG_PRINTF(DBG_ERROR, "user:[%s] not found\n", ngx_print(user_name, USER_NAME_MAX_LEN, &p_req->ngx_user_name));

        p_user_interface_parse_block->code = USER_CODE_TYPE_USER_NOT_FOUND;
        goto EXIT;
    }

    if (p_user_block->del_flag == 1) {
        DBG_PRINTF(DBG_ERROR, "user:[%s] del already\n", ngx_print(user_name, USER_NAME_MAX_LEN, &p_req->ngx_user_name));
        p_user_interface_parse_block->code = USER_CODE_TYPE_USER_ALREADY_DEL;
        goto EXIT;
    }

    struct user_account_block *p_resp = &p_user_interface_parse_block->resp.account;

    strncpy(p_resp->user_name, p_user_block->user_name, USER_NAME_MAX_LEN);
    p_resp->end_time = p_user_block->end_time;
    p_resp->total_flow = p_user_block->total_flow;
    p_resp->used_flow = p_user_block->used_flow;

    p_user_interface_parse_block->code = USER_CODE_TYPE_SUCCESS;

    DBG_PRINTF(DBG_ERROR, "query user:[%u][%s] success\n",
            p_user_block->user_id,
            p_user_block->user_name);

EXIT:
    user_table_unlock();
}


struct user_node *user_find_and_check(struct user_sk_node *sk, enum user_code_type *code, ngx_str_t *p_user_name)
{
    struct user_table *p_table = &g_user_table;

    struct user_node *p_user_block = DHASH_FIND(g_user_table, &p_table->hash, p_user_name);

    if (NULL == p_user_block) {
        char user_name[200];
        DBG_PRINTF(DBG_WARNING, "user %s not found, fd: %d\n",
                ngx_print(user_name, sizeof(user_name) - 1, p_user_name),
                sk->fd);
        *code = USER_CODE_TYPE_AUTH_FAIL;
#ifdef USER_BLOCK_ENABLE
        control_insert_ip_blacklist(sk->ip, 2);
#endif
        return NULL;
    }

    if (p_user_block->end_time < time(NULL)) {
        DBG_PRINTF(DBG_WARNING, "user %s, expire valid date: %u\n",
                p_user_block->user_name,
                p_user_block->end_time);
        *code = USER_CODE_TYPE_EXPIRE;
#ifdef USER_BLOCK_ENABLE
        control_insert_ip_blacklist(sk->ip, 2 * 60);
#endif
        return NULL;
    }

    return p_user_block;
}



void user_socket_deal_read_data(struct user_sk_node *sk, struct user_interface_parse_block *p_user_interface_parse_block)
{
    user_data_parse(sk, p_user_interface_parse_block);

    switch(p_user_interface_parse_block->type) {
    case USER_REQ_TYPE_NEED_MORE:
    case USER_REQ_TYPE_UNKNOWN:
        break;

    case USER_REQ_TYPE_ADD_ACCOUNT:
        user_add_account(sk, p_user_interface_parse_block);
        break;

    case USER_REQ_TYPE_MDF_ACCOUNT:
        user_mdf_account(sk, p_user_interface_parse_block);
        break;

    case USER_REQ_TYPE_DEL_ACCOUNT:
        user_del_account(sk, p_user_interface_parse_block);
        break;

    case USER_REQ_TYPE_QUERY_ACCOUNT:
        user_query_account(sk, p_user_interface_parse_block);
        break;

    case USER_REQ_TYPE_DEBUG:
        p_user_interface_parse_block->code = user_debug(p_user_interface_parse_block);
        break;

    default:
        DBG_PRINTF(DBG_WARNING, "seq_id: %u, unknown type: %d\n",
                sk->seq_id,
                p_user_interface_parse_block->type);
        break;
    }

    return;
}

const char *g_http_response =
"HTTP/1.1 %d OK\r\n"
"Content-Type: text/plain; charset=utf-8\r\n"
"X-Powered-By: PHP/5.6.36\r\n"
"Pragma: no-cache\r\n"
"Content-Length: %d\r\n"
"Connection: close\r\n\r\n";

int user_make_json_resp(char *buf, int buf_size, struct user_interface_parse_block *p_resp_info)
{
    struct json_object *resp_object = NULL;
    struct json_object *array_object = NULL;
    int ret = 0;

    ret = snprintf(buf, buf_size, "{code %d}", p_resp_info->code);
    resp_object = json_object_new_object();
    if (NULL == resp_object) {
        DBG_PRINTF(DBG_ERROR, "new json object failed!\n");
        goto JSON_RESP_END;
    }

    array_object = json_object_new_array();
    if (NULL == array_object) {
        DBG_PRINTF(DBG_ERROR, "new json object failed!\n");
        goto JSON_RESP_END;
    }

    json_object_object_add(resp_object, "code", json_object_new_int(p_resp_info->code));
    int index = p_resp_info->code;
    if (index >= 0 && index < (sizeof(g_user_code_type_str) / sizeof(char *)))
        json_object_object_add(resp_object, "value", json_object_new_string(g_user_code_type_str[index]));
    if (p_resp_info->code == USER_CODE_TYPE_SUCCESS) {
        switch(p_resp_info->type) {
        case USER_REQ_TYPE_ADD_ACCOUNT: {
            struct user_account_block *p_resp = &p_resp_info->resp.account;
            json_object_object_add(resp_object, "user_name", json_object_new_string(p_resp->user_name));
            json_object_object_add(resp_object, "total_flow", json_object_new_int(p_resp->total_flow));
            break;
        }

        case USER_REQ_TYPE_QUERY_ACCOUNT: {
            struct user_account_block *p_resp = &p_resp_info->resp.account;
            json_object_object_add(resp_object, "user_name", json_object_new_string(p_resp->user_name));
            json_object_object_add(resp_object, "total_flow", json_object_new_int(p_resp->total_flow));
            json_object_object_add(resp_object, "used_flow", json_object_new_int(p_resp->used_flow));
            char buffer[100];
            DBG_PRINTF(DBG_ERROR, "%s!\n",date_format(buffer, 100, p_resp->end_time));
            json_object_object_add(resp_object, "expire_date", json_object_new_string(date_format(buffer, 100, p_resp->end_time)));
            break;
        }

        default:
            break;

        }
    }

    ret = snprintf(buf, buf_size, "%s", json_object_to_json_string(resp_object));
JSON_RESP_END:
    if (resp_object)
        json_object_put(resp_object);
    if (array_object)
        json_object_put(array_object);

    return ret;
}

const ngx_str_t g_split_dos = ngx_string("dos");
const ngx_str_t g_split_html = ngx_string("html");

#if 0
int user_make_txt_resp(char *buf, int buf_size, struct user_interface_parse_block *p_resp_info)
{
    int ret_len = 0;
    char split[USER_SPLIT_LEN + 1] = "\n";
    if (0 < p_resp_info->req.open.split.len
            && p_resp_info->req.open.split.len < USER_SPLIT_LEN) {
        if (0 == ngx_cmp((ngx_str_t *)&g_split_dos, &p_resp_info->req.open.split))
            strncpy(split, "\r\n", USER_SPLIT_LEN);
        else if (0 == ngx_cmp((ngx_str_t *)&g_split_html, &p_resp_info->req.open.split))
            strncpy(split, "<br/>", USER_SPLIT_LEN);
        else {
            memcpy(split, p_resp_info->req.open.split.data, p_resp_info->req.open.split.len);
            split[p_resp_info->req.open.split.len] = 0;
        }
    }

    if (p_resp_info->code == IP_PROXY_ERR_SUCCESS)
    {
        struct user_open_block *p_open = &p_resp_info->req.open;
        struct user_open_ack_block *p_open_ack = &p_resp_info->resp.open_ack;
        if (IP_PROXY_CONTROL_OPEN == p_resp_info->status)
        {
            switch(p_open->fmt) {
            default: {
                ret_len += snprintf(buf, buf_size - ret_len, "%d%s%u%s%u%s%d",
                        p_resp_info->code,
                        split,
                        p_open_ack->left_ip,
                        split,
                        p_open_ack->left_sec,
                        split,
                        p_open_ack->num);

                int i;
                for (i = 0; i < p_open_ack->num; i++)
                {
                    ret_len += snprintf(buf + ret_len, buf_size - ret_len, "%s:%hu",
                            split,
                            p_open_ack->ip_info[i].port);
                }
                break;
            }
            }
        }
        else if (IP_PROXY_CONTROL_QUERY == p_resp_info->status)
        {
            ret_len += snprintf(buf, buf_size - ret_len, "%d%s%u%s%u%s%u%s%u",
                    p_resp_info->code,
                    split,
                    p_open_ack->left_ip,
                    split,
                    p_open_ack->left_sec,
                    split,
                    p_open_ack->used,
                    split,
                    p_open_ack->inuse);
            int i;
            for (i = 0; i < p_open_ack->num; i++)
            {
                ret_len += snprintf(buf + ret_len, buf_size - ret_len, "%s%hu",
                        split,
                        p_open_ack->ip_info[i].port);
            }
        }
        else if (IP_PROXY_CONTROL_QUERY_INFO == p_resp_info->status)
        {
#ifdef MANU_FLOW
            ret_len += snprintf(buf, buf_size - ret_len, "%d%s%u%s%u%s%u%s%u%s%u",
#else
                    ret_len += snprintf(buf, buf_size - ret_len, "%d%s%u%s%u%s%u%s%u",
#endif
                        p_resp_info->code,
                        split,
                        p_open_ack->left_ip,
                        split,
                        p_open_ack->left_sec,
                        split,
                        p_open_ack->used,
                        split,
                        p_open_ack->inuse
#ifdef MANU_FLOW
                        ,split,
                        p_open_ack->flow_used_mb
#endif
                        );
                    }
                    else if (IP_PROXY_CONTROL_QUERY_WHITELIST == p_resp_info->status)
                    {
                        struct user_whitelist_block *p_resp = &p_resp_info->resp.whitelist;
                        char ip_str[16];
                        uint32_t ip = 0;
                        int i;

                        ret_len += snprintf(buf, buf_size - ret_len, "%d%s%d",
                                p_resp_info->code,
                                split,
                                p_resp->num);

                        for (i = 0; i < p_resp->num; i++) {
                            ip = htonl(p_resp->ip[i]);
                            ret_len += snprintf(buf + ret_len, buf_size - ret_len, "%s%s",
                                    split,
                                    inet_ntop(AF_INET, &ip, ip_str, sizeof(ip_str)));
                        }
                    }
        else
        {
            ret_len += snprintf(buf, buf_size - ret_len, "%d", p_resp_info->code);
        }
    }
    else
    {
        ret_len += snprintf(buf, buf_size - ret_len, "%d", p_resp_info->code);
    }


    return ret_len;
}
#endif


int user_make_http_resp(struct user_sk_node *sk, struct user_interface_parse_block *p_resp_info)
{
    struct user_resp_buf_node *p_resp_node = sk->p_recv_node;
    if (p_resp_node == NULL) {
        DBG_PRINTF(DBG_WARNING, "socket %d, malloc error, drop data!\n", sk->seq_id);
        return -1;
    }
    sk->p_recv_node = NULL;

    p_resp_node->pos = 200;
    p_resp_node->end = 200;

    int resp_len;
    resp_len = user_make_json_resp((char *)p_resp_node->buf + p_resp_node->end, USER_MAX_RESP_BUF_SIZE - p_resp_node->end - 1, p_resp_info);

    if (resp_len < 1) {
        DBG_PRINTF(DBG_WARNING, "socket %d, resp_len: %d\n", sk->seq_id, resp_len);
        free_user_resp_buf_node(p_resp_node);
        return -1;
    }
    DBG_PRINTF(DBG_NORMAL, "resp_len %d!\n", resp_len);

    char http_header_str[200];
    int header_len = 0;

    header_len = snprintf(http_header_str, 200, g_http_response, 200, resp_len);
    if (header_len < 1 || header_len >= 200) {
        DBG_PRINTF(DBG_WARNING, "socket %d, header_len: %d\n", sk->seq_id, header_len);
        free_user_resp_buf_node(p_resp_node);
        return -1;
    }
    p_resp_node->pos -= header_len;
    p_resp_node->end += resp_len;
    memcpy(p_resp_node->buf + p_resp_node->pos, http_header_str, header_len);
    list_add_tail(&p_resp_node->list_head, &sk->send_list);

    return 0;
}

void user_socket_read_cb(void *v)
{
    struct user_sk_node *sk = (struct user_sk_node *)v;
    int fd = sk->fd;
    uint32_t seq_id = sk->seq_id;

    if (sk->status != SOCKET_STATUS_NEW) {
        DBG_PRINTF(DBG_WARNING, "seq_id %u:%d status %d, ip,port: %u,%hu\n",
                seq_id,
                fd,
                sk->status,
                sk->ip,
                sk->port);

        sk->exit_cb((void *)sk);
        return;
    }

    sk->last_active = time(NULL);
    user_move_node_to_list(sk, sk->type);
    while(1) {
        struct user_resp_buf_node *p_recv_node = sk->p_recv_node;
        if (p_recv_node == NULL) {
            p_recv_node = malloc_user_resp_buf_node();
            if (p_recv_node == NULL) {
                DBG_PRINTF(DBG_WARNING, "seq_id %u:%d, no avaiable space, drop data!\n", seq_id, fd);
                break;
            } else {
                p_recv_node->pos = p_recv_node->end = 0;
                sk->p_recv_node = p_recv_node;
            }
        }

        if (sk->p_recv_node->end >= USER_MAX_RESP_BUF_SIZE) {
            DBG_PRINTF(DBG_ERROR, "user %u:%d, critical pos: %hu, end: %hu\n",
                    seq_id,
                    fd,
                    sk->p_recv_node->pos,
                    sk->p_recv_node->end);
            DBG_DUMP_HEX(DBG_ERROR, sk->p_recv_node->buf + sk->p_recv_node->pos, sk->p_recv_node->end - sk->p_recv_node->pos);
            if (sk->exit_cb)
                sk->exit_cb((void *)sk);
            break;
        }

        uint16_t to_recv = USER_MAX_RESP_BUF_SIZE - p_recv_node->end;
        int nread = recv(fd, p_recv_node->buf + p_recv_node->end, to_recv, MSG_DONTWAIT);
        if (nread > 0) {
            sk->p_recv_node->end += nread;

            struct user_interface_parse_block auth_block;
            user_socket_deal_read_data(sk, &auth_block);

            if (auth_block.type != USER_REQ_TYPE_NEED_MORE) {
                DBG_PRINTF(DBG_NORMAL, "seq_id %u:%d, code: %d\n", seq_id, fd, auth_block.code);
                if (user_make_http_resp(sk, &auth_block) == 0) {
                    sk->status = SOCKET_STATUS_EXIT_AFTER_SEND;
                    sk->write_cb((void *)sk);
                } else {
                    sk->exit_cb((void *)sk);
                }
                break;
            }

            continue;
        }

        if (nread == 0) {
            DBG_PRINTF(DBG_WARNING, "seq_id %u:%d,  closed by peer\n", seq_id, fd);
            sk->exit_cb((void *)sk);
            break;
        }

        if (nread < 0) {
            if (errno == EINTR) {
                DBG_PRINTF(DBG_ERROR, "seq_id %u:%d, need recv again!\n", seq_id, fd);
                continue;
            } else if (errno == EAGAIN) {
                DBG_PRINTF(DBG_WARNING, "seq_id %u:%d, need recv next!\n", seq_id, fd);
                break;
            } else {
                DBG_PRINTF(DBG_ERROR, "seq_id %u:%d, errno: %d, error msg: %s!\n", seq_id, fd, errno, strerror(errno));
                sk->exit_cb((void *)sk);
                break;
            }
        }

    }

}

void user_socket_write_cb(void *v)
{
    struct user_sk_node *sk = (struct user_sk_node *)v;
    struct user_socket_table    *p_table = sk->p_table;
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
        sk->last_active = time(NULL);
        struct user_resp_buf_node *p_entry = list_entry(p_list, struct user_resp_buf_node, list_head);

        DBG_PRINTF(DBG_NORMAL, "seq_id %u:%d, send buf pos %hu, end %hu\n",
                seq_id,
                fd,
                p_entry->pos,
                p_entry->end);

        int nwrite = 0;
        int to_write = p_entry->end - p_entry->pos;
        do {
            p_entry->pos = p_entry->pos + nwrite;
            to_write = p_entry->end - p_entry->pos;
            if (to_write == 0)
                break;

            DBG_DUMP_HEX(DBG_NORMAL, (const uint8_t *)(p_entry->buf + p_entry->pos), to_write);
            nwrite = send(fd, p_entry->buf + p_entry->pos, to_write, 0);
            DBG_PRINTF(DBG_NORMAL, "seq_id %u:%d, nwrite: %d\n", seq_id, fd, nwrite);
        }while(nwrite > 0);

        if (to_write == 0) {
            DBG_PRINTF(DBG_NORMAL, "seq_id %u:%d, no data to write!\n", seq_id, fd);

            list_del(&p_entry->list_head);
            free_user_resp_buf_node(p_entry);
            continue;
        }

        if (nwrite < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                DBG_PRINTF(DBG_WARNING, "seq_id %u:%d, cannot write!\n", seq_id, fd);
                modify_event(p_table->epfd, fd, (void *)sk, EPOLLIN | EPOLLOUT);// | EPOLLET);
                sk->blocked = 1;
                goto LT_USER_WRITE_EXIT;
            } else {
                sk->exit_cb((void *)sk);
                DBG_PRINTF(DBG_ERROR, "seq_id %u:%d, errno: %d, error msg: %s!\n", seq_id, fd, errno, strerror(errno));
                return;
            }
        } else {
            DBG_PRINTF(DBG_ERROR, "critical seq_id %u:%d, nwrite: %d, to_write: %d\n", seq_id, fd, nwrite, to_write);
        }
    }

    if (sk->status == SOCKET_STATUS_EXIT_AFTER_SEND) {
        sk->exit_cb((void *)sk);
        return;
    }
    modify_event(p_table->epfd, fd, (void *)sk, EPOLLIN);// | EPOLLET);

LT_USER_WRITE_EXIT:
    DBG_PRINTF(DBG_WARNING, "seq_id %u:%d, need next write\n", seq_id, fd);
    return;
}

void user_socket_exit_cb(void *v)
{
    struct user_sk_node *sk = (struct user_sk_node *)v;
    struct user_socket_table    *p_table = sk->p_table;

    if (sk->status == SOCKET_STATUS_DEL) {
        DBG_PRINTF(DBG_ERROR, "seq_id %u:%d critical error alread del\n",
                sk->seq_id,
                sk->fd);
        return;
    }

    delete_event(p_table->epfd, sk->fd, sk, EPOLLIN | EPOLLOUT);

    close(sk->fd);
    sk->status = SOCKET_STATUS_DEL;

    user_move_node_to_list(sk, USER_SOCKET_TYPE_DEL);

    if (g_main_debug >= DBG_NORMAL) {
        char ip_str[30];
        uint32_t ip = htonl(sk->ip);
        DBG_PRINTF(DBG_WARNING, "exit seq_id %u:%d connect from %s:%d, ttl: %d\n",
                sk->seq_id,
                sk->fd,
                inet_ntop(AF_INET, &ip, ip_str, sizeof(ip_str)),
                sk->port,
                time(NULL) - sk->last_active);
    }
}

/*
   1. 从当前链表中移除
   2. 释放 recv_node
   3. 释放 send_list
   4. 释放自身
   */
void user_socket_del_cb(void *v)
{
    struct user_sk_node *sk = (struct user_sk_node *)v;
    struct user_socket_table    *p_table = sk->p_table;

    if (sk->type != USER_SOCKET_TYPE_DEL) {
        DBG_PRINTF(DBG_ERROR, "critical error %u:%d last_active: %d type: %hhu status: %hhu\n",
                sk->seq_id,
                sk->fd,
                sk->last_active,
                sk->type,
                sk->status);
    }

    struct list_table *p_list_table = &p_table->list_head[sk->type];

    list_del(&sk->list_head);
    p_list_table->num--;

    if (sk->p_recv_node)
        free_user_resp_buf_node(sk->p_recv_node);

    int count = 0;
    struct list_head            *p_list = NULL;
    struct list_head            *p_next = NULL;
    list_for_each_safe(p_list, p_next, &sk->send_list) {
        struct user_resp_buf_node *p_entry = list_entry(p_list, struct user_resp_buf_node, list_head);
        count++;
        list_del(&p_entry->list_head);
        free_user_resp_buf_node(p_entry);
    }

    if (g_main_debug >= DBG_NORMAL) {
        char ip_str[32];
        uint32_t ip = htonl(sk->ip);
        DBG_PRINTF(DBG_WARNING, "del seq_id: %u connect from %s:%d, last_active: %d, free send node: %d\n",
                sk->seq_id,
                inet_ntop(AF_INET, &ip, ip_str, sizeof(ip_str)),
                sk->port,
                sk->last_active,
                count);
    }

    free_user_socket_node(sk);
}

static void user_socket_handle_accpet_cb(void *v)
{
    struct user_sk_node *sk = (struct user_sk_node *)v;

    struct sockaddr_in  client_addr;
    socklen_t           length          = sizeof(client_addr);
    int                 new_socket      = accept(sk->fd, (struct sockaddr*)&client_addr, &length);

    if (new_socket < 0) {
        DBG_PRINTF(DBG_ERROR, "Accept Failed! error no: %d, error msg: %s\n", errno, strerror(errno));
        return;
    }

    uint32_t ip = ntohl(client_addr.sin_addr.s_addr);

#ifdef USER_BLOCK_ENABLE
    if (!control_is_user_ip_valid(ip)) {
        if (g_temp_debug >= DBG_WARNING) {
            char ip_str[32];
            DBG_PRINTF(DBG_WARNING, "invalid ip, new socket %d connect from %s:%hu\n",
                    new_socket,
                    inet_ntop(AF_INET, &client_addr.sin_addr.s_addr, ip_str, sizeof(ip_str)),
                    client_addr.sin_port);
        }
        close(new_socket);
        return;
    }
#endif

    struct user_sk_node *p_node = malloc_user_socket_node();
    if (p_node == NULL) {
        char ip_str[32];
        DBG_PRINTF(DBG_ERROR, "user %u new socket %d connect from %s:%hu failed\n",
                0,
                new_socket,
                inet_ntop(AF_INET, &client_addr.sin_addr.s_addr, ip_str, sizeof(ip_str)),
                client_addr.sin_port);
        close(new_socket);
        return;
    }

    struct user_socket_table *p_table = sk->p_table;

    p_node->fd              = new_socket;
    p_node->ip              = ip;
    p_node->port            = ntohs(client_addr.sin_port);
    p_node->p_table         = p_table;
    p_node->p_recv_node     = NULL;
    p_node->last_active     = time(NULL);
    p_node->start_time      = p_node->last_active;
    p_node->status          = SOCKET_STATUS_NEW;
    p_node->type            = USER_SOCKET_TYPE_WORKER;
    p_node->read_cb        = user_socket_read_cb;
    p_node->write_cb       = user_socket_write_cb;
    p_node->exit_cb        = user_socket_exit_cb;
    p_node->del_cb         = user_socket_del_cb;
    INIT_LIST_HEAD(&p_node->send_list);

    struct list_table *p_list_table = &p_table->list_head[p_node->type];

    list_add_fe(&p_node->list_head, &p_list_table->list_head);
    p_list_table->num++;

    set_none_block(p_node->fd);
    add_event(p_table->epfd, p_node->fd, p_node, EPOLLIN);

    if (g_main_debug >= DBG_NORMAL) {
        char ip_str[32];
        DBG_PRINTF(DBG_WARNING, "new socket %u:%d connect from %s:%hu success\n",
                p_node->seq_id,
                p_node->fd,
                inet_ntop(AF_INET, &client_addr.sin_addr.s_addr, ip_str, sizeof(ip_str)),
                client_addr.sin_port);
    }
    return;
}

void user_event_init(struct user_socket_table *p_table)
{
    p_table->events = (struct epoll_event *)malloc(sizeof(struct epoll_event) * USER_EPOLL_ACCEPT_MAX_EVENTS);
    if (p_table->events == NULL)
        exit(EXIT_FAILURE);

    p_table->epfd = epoll_create(USER_EPOLL_ACCEPT_MAX_EVENTS);
    DBG_PRINTF(DBG_WARNING, "user %d\n", p_table->epfd);

    uint32_t listen_ip = 0;
    uint16_t listen_port = USER_PORT;
    char ip_str[30];
    uint32_t ip = htonl(listen_ip);
    /* 监听在某端口上，处理用户认证数据 */
    int server_socket_fd = create_listen_socket_at_address(listen_ip, listen_port, USER_SOCKET_LISTEN_BACKLOG);
    if (server_socket_fd < 0) {
        DBG_PRINTF(DBG_ERROR, "create listen socket failed at %s:%hu, errnum: %d\n",
                inet_ntop(AF_INET, &ip, ip_str, sizeof(ip_str)),
                listen_port,
                server_socket_fd);
        exit(EXIT_FAILURE);
    } else {
        DBG_PRINTF(DBG_WARNING, "create listen socket success at %s:%hu, server_socket_fd: %d\n",
                inet_ntop(AF_INET, &ip, ip_str, sizeof(ip_str)),
                listen_port,
                server_socket_fd);
    }

    struct user_sk_node *p_node = malloc_user_socket_node();
    if (p_node == NULL) {
        DBG_PRINTF(DBG_ERROR, "new listen socket %d at %hu failed\n",
                server_socket_fd,
                listen_port);
        close(server_socket_fd);
        return;
    }

    p_node->fd              = server_socket_fd;
    p_node->ip              = listen_ip;
    p_node->port            = listen_port;
    p_node->p_table         = p_table;
    p_node->p_recv_node     = NULL;
    p_node->last_active     = time(NULL);
    p_node->status          = SOCKET_STATUS_NEW;
    p_node->type            = 0;
    p_node->read_cb        = user_socket_handle_accpet_cb;
    p_node->write_cb       = NULL;
    p_node->exit_cb        = user_socket_exit_cb;
    p_node->del_cb         = user_socket_del_cb;
    INIT_LIST_HEAD(&p_node->send_list);

    set_none_block(p_node->fd);
    add_event(p_table->epfd, p_node->fd, p_node, EPOLLIN);

    DBG_PRINTF(DBG_ERROR, "new listen socket %d at %hu success\n",
            server_socket_fd,
            listen_port);

}

void user_socket_init()
{
    resp_buf_table_init();
    user_socket_buf_table_init();

    struct user_socket_table *p_table = (struct user_socket_table *)&g_user_socket_table;

    p_table->index = 0;
    p_table->thread_id = 0;
    pthread_mutex_init(&p_table->mutex, NULL);
    strncpy(p_table->table_name, "g_user_socket_table", TABLE_NAME_LEN);

    int i;
    for (i = 0; i < USER_SOCKET_TYPE_MAX; i++) {
        INIT_LIST_HEAD(&p_table->list_head[i].list_head);
        p_table->list_head[i].num = 0;
    }

    user_event_init(p_table);
}

void user_old_process(struct user_socket_table *p_table, uint8_t type, int timeout_sec)
{
    int                         count = 0;
    time_t                      kill_time = time(NULL) - timeout_sec;
    struct list_table           *p_list_table = &p_table->list_head[type];
    uint32_t                    total_num = p_list_table->num;

    struct list_head            *p_list = NULL;
    struct list_head            *p_next = NULL;
    list_for_each_prev_safe(p_list, p_next, &p_list_table->list_head) {
        struct user_sk_node *p_entry = list_entry(p_list, struct user_sk_node, list_head);
        if (p_entry->status == SOCKET_STATUS_NEW) {
            if (p_entry->last_active < kill_time) {
                count++;
                p_entry->exit_cb((void *)p_entry);
            } else {
                break;
            }
        } else {
            DBG_PRINTF(DBG_WARNING, "user %u:%d critical error, status: %d\n",
                    p_entry->seq_id,
                    p_entry->fd,
                    p_entry->status);
        }
    }

    if (count)
        DBG_PRINTF(DBG_WARNING, "%s list table: %d total_num: %u, old: %d\n", p_table->table_name, type, total_num, count);
}

/*
   对 del 链中的节点执行回收删除操作
   */
void user_del_process(struct list_table *p_list_table)
{
    int                         count = 0;
    struct list_head            *p_list = NULL;
    struct list_head            *p_next = NULL;
    list_for_each_safe(p_list, p_next, &p_list_table->list_head) {
        struct user_sk_node *p_entry = list_entry(p_list, struct user_sk_node, list_head);
        if (p_entry->del_cb) {
            count++;
            p_entry->del_cb((void *)p_entry);
        }
    }
    if (count > 50)
        DBG_PRINTF(DBG_WARNING, "del %d\n", count);

}

void *user_socket_process(void *arg)
{
    struct user_socket_table *p_table = (struct user_socket_table *)&g_user_socket_table;
    time_t last_time = time(NULL);
    time_t last_old_time = time(NULL);

    prctl( PR_SET_NAME, __FUNCTION__);

    DBG_PRINTF(DBG_WARNING, "enter\n");

    while(g_main_running) {
        int nfds = epoll_wait(p_table->epfd, p_table->events, USER_EPOLL_ACCEPT_MAX_EVENTS, 1000);

        int i;
        for( i= 0; i < nfds; ++i) {
            struct user_sk_node *sk = (struct user_sk_node *)(p_table->events[i].data.ptr);
            if(p_table->events[i].events & EPOLLIN) {
                sk->read_cb((void *)sk);
            } else if(p_table->events[i].events & EPOLLOUT) {
                sk->blocked = 0;
                sk->write_cb((void *)sk);
            } else {
                DBG_PRINTF(DBG_ERROR, "ip:%u, port:%d unknown event!\n", sk->ip, sk->port);
            }
        }

        time_t now = time(NULL);
        if ((now - last_time) > USER_SOCKET_CHECK_PERIOD_SECONDS) {
            last_time = now;
            user_old_process(p_table, USER_SOCKET_TYPE_WORKER, USER_SOCKET_TIMEOUT_MAX_SECONDS);
        }
        user_del_process(&p_table->list_head[USER_SOCKET_TYPE_DEL]);

        if ((now - last_old_time) > USER_IP_OLD_CHECK_PERIOD_SECONDS) {
            bool new_day = is_new_day(last_old_time, now);
            last_old_time = now;

            user_ip_old_process(new_day);
        }
    }

    DBG_PRINTF(DBG_WARNING, "leave\n");

    exit(EXIT_SUCCESS);
}

#endif

