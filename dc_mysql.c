#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <mysql.h>
#include <errno.h>
#include <pthread.h>
#include <sys/prctl.h>
#include <pthread.h>
#include "dc_mysql.h"
#include "log.h"
#include "buff.h"

MYSQL g_mysql_con;
extern int g_main_running;
extern struct ctx g_ctx;

struct mysql_manage_table g_mysql_table;

const char *g_mysql_charset_sql_str = "SET NAMES utf8";


const char *g_mysql_db_name[MYSQL_DB_NAME_MAX] = {
    "crossnet",
    "crossnet_log"
};

const char *g_mysql_init_db_sql = "CREATE DATABASE IF NOT EXISTS `%s` CHARACTER SET utf8 COLLATE utf8_general_ci;";

const char *g_mysql_crossnet_table_name[MYSQL_CROSSNET_TABLE_NAME_MAX] = {
    "account",
    "domain_list",
    "record"
};

const char *g_mysql_crossnet_select_column_str[MYSQL_CROSSNET_TABLE_NAME_MAX] = {
    "user_id,user_name,password,domain,start_time,end_time,total_flow,used_flow,del_flag,time",
    "user_id,domain,used_flow,time",
};

const char *g_mysql_crossnet_init_table_sql[MYSQL_CROSSNET_TABLE_NAME_MAX] = {
    "CREATE TABLE IF NOT EXISTS `%s`.`%s` ("
        "  `user_id` int(10) unsigned NOT NULL AUTO_INCREMENT,"
        "  `user_ip` int(20) unsigned NOT NULL DEFAULT '0',"
        "  `user_name` char(65) NOT NULL DEFAULT '',"
        "  `password` char(65) NOT NULL DEFAULT '',"
        "  `domain` varchar(200) NOT NULL DEFAULT '',"
        "  `email` varchar(200) NOT NULL DEFAULT '',"
        "  `start_time` int(20) unsigned NOT NULL DEFAULT '0',"
        "  `end_time` int(20) unsigned NOT NULL DEFAULT '0',"
        "  `total_flow` bigint unsigned NOT NULL DEFAULT '0',"
        "  `used_flow` bigint unsigned NOT NULL DEFAULT '0',"
        "  `del_flag` int(10) unsigned NOT NULL DEFAULT '0',"
        "  `time` int(20) unsigned NOT NULL DEFAULT '0',"
        "  PRIMARY KEY (`user_id`),"
        "  UNIQUE KEY `user_name` (`user_name`),"
        "  UNIQUE KEY `email` (`email`)"
        ") ENGINE=InnoDB DEFAULT CHARSET=utf8;",

    "CREATE TABLE IF NOT EXISTS `%s`.`%s` ("
        "  `user_id` int(10) unsigned NOT NULL DEFAULT '0',"
        "  `domain` varchar(200) NOT NULL DEFAULT '',"
        "  `used_flow` bigint unsigned NOT NULL DEFAULT '0',"
        "  `time` int(20) unsigned NOT NULL DEFAULT '0',"
        "  KEY (`user_id`),"
        "  UNIQUE KEY `domain` (`domain`)"
        ") ENGINE=InnoDB DEFAULT CHARSET=utf8;",

    "CREATE TABLE IF NOT EXISTS `%s`.`%s` ("
        "  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,"
        "  `user_id` int(10) unsigned NOT NULL DEFAULT '0',"
        "  `recharge` int(10) unsigned NOT NULL DEFAULT '0',"
        "  `used_flow` bigint unsigned NOT NULL DEFAULT '0',"
        "  `time` int(20) unsigned NOT NULL DEFAULT '0',"
        "  PRIMARY KEY (`id`),"
        "  KEY (`user_id`)"
        ") ENGINE=InnoDB DEFAULT CHARSET=utf8;",

};

const char *g_mysql_crossnet_insert_head_format_str[MYSQL_STORE_TYPE_MAX] = {
    "INSERT INTO `%s`.`%s` %s VALUES ('%u','%s','%s','%s','%u','%u','%lu','%lu','%u','%u') %s",
};

const char *g_mysql_crossnet_insert_column_str[MYSQL_STORE_TYPE_MAX] = {
    "(user_id,user_name,password,domain,start_time,end_time,total_flow,used_flow,del_flag,time)",
};

const char *g_mysql_crossnet_insert_value_format_str[MYSQL_STORE_TYPE_MAX] = {
    ",('%u','%s','%s','%s','%u','%u','%lu','%lu','%u','%u')",
};

const char *g_mysql_crossnet_insert_tail_format_str[MYSQL_STORE_TYPE_MAX] = {
    " ON DUPLICATE KEY UPDATE user_id=VALUES(user_id),user_name=VALUES(user_name),password=VALUES(password),domain=VALUES(domain),end_time=VALUES(end_time),total_flow=VALUES(total_flow),used_flow=VALUES(used_flow),del_flag=VALUES(del_flag),time=VALUES(time)",/* account */
};

inline void dc_mysql_lock()
{
    pthread_mutex_lock(&g_mysql_table.mutex);
}

inline void dc_mysql_unlock()
{
    pthread_mutex_unlock(&g_mysql_table.mutex);
}


#if 1

struct buff_table g_mysql_store_buf_table;

void mysql_store_buf_table_init()
{
    buff_table_init(&g_mysql_store_buf_table, USER_SOCKET_BUF_MAX_NUM, sizeof(struct mysql_store_node), "g_mysql_store_buf_table");
}

inline struct mysql_store_node *malloc_mysql_store_node()
{
    return (struct mysql_store_node *)buff_table_malloc_node(&g_mysql_store_buf_table);
}

inline void free_mysql_store_node(struct mysql_store_node *p_node)
{
    buff_table_free_node(&g_mysql_store_buf_table, &p_node->list_head);
}

void display_g_mysql_store_buff_table()
{
    display_buff_table(&g_mysql_store_buf_table);
}

#endif

int dc_mysql_connect_init()
{
    if (NULL == mysql_init(&g_mysql_con)) {
        DBG_PRINTF(DBG_WARNING,"mysql_init failed, error msg: %s\n", strerror(errno));
        return -1;
    }

    if (mysql_real_connect(&g_mysql_con, "127.0.0.1", g_ctx.mysql_name, g_ctx.mysql_pass, NULL, g_ctx.mysql_port, NULL, CLIENT_MULTI_STATEMENTS)) {
        return 0;
    } else {
        DBG_PRINTF(DBG_WARNING,"mysql_real_connect failed, error msg: %s\n", strerror(errno));
        return -1;
    }
}

int dc_mysql_real_execute(const char *sql_buf)
{
    int ret = 0;
    int err_try_num = 0;
    int sql_errno = 0;

AGAIN:
    ret = mysql_query(&g_mysql_con, sql_buf);
    if (0 == ret)
        return 0;
    else {
        sql_errno = mysql_errno(&g_mysql_con);
        DBG_PRINTF(DBG_WARNING,"%s\n", sql_buf);
        DBG_PRINTF(DBG_WARNING,"sql execute error %d: %s\n", sql_errno, mysql_error(&g_mysql_con));
        if (sql_errno == 2006
                || sql_errno == 2013) {
            if (0 == dc_mysql_connect_init()) {
                if (err_try_num++ < MYSQL_EXECUTE_MAX_TRY_NUM) {
                    DBG_PRINTF(DBG_WARNING,"mysql execute %d times!\n", err_try_num);
                    goto AGAIN;
                }
            }
        }
        return -1;
    }
}

int dc_mysql_charset_init()
{
    return dc_mysql_real_execute(g_mysql_charset_sql_str);
}

int dc_mysql_db_init()
{
    int i;
    char sql_buf[MYSQL_BUF_LEN];

    for (i = 0; i < MYSQL_DB_NAME_MAX; i++) {   
        snprintf(sql_buf, MYSQL_BUF_LEN, g_mysql_init_db_sql, g_mysql_db_name[i]);
        dc_mysql_real_execute(sql_buf);
    }

    return 0;
}

int dc_mysql_table_init()
{
    int i, ret;
    char sql_buf[MYSQL_BUF_LEN];

    for (i = 0; i < MYSQL_CROSSNET_TABLE_NAME_MAX; i++) {   
        snprintf(sql_buf, MYSQL_BUF_LEN, g_mysql_crossnet_init_table_sql[i], g_mysql_db_name[MYSQL_DB_NAME_CROSSNET], g_mysql_crossnet_table_name[i]);

        ret = dc_mysql_real_execute(sql_buf);
        if (0 == ret) {
            DBG_PRINTF(DBG_WARNING, "Create table %s success\n", g_mysql_crossnet_table_name[i]);
        } else {
            DBG_PRINTF(DBG_ERROR, "sql: %s\n", sql_buf);
        }
    }

    return 0;
}


int dc_mysql_update_account_table()
{
    char sql_buf[MYSQL_BUF_LEN];
    int  ret = 0;
    MYSQL_RES *res_ptr;
    MYSQL_ROW sql_row;

    snprintf(sql_buf, MYSQL_BUF_LEN, "SELECT %s FROM `%s`.`%s`", 
            g_mysql_crossnet_select_column_str[MYSQL_CROSSNET_TABLE_NAME_ACCOUNT],
            g_mysql_db_name[MYSQL_DB_NAME_CROSSNET],
            g_mysql_crossnet_table_name[MYSQL_CROSSNET_TABLE_NAME_ACCOUNT]);

    ret = dc_mysql_real_execute(sql_buf);    
    if (0 != ret) {
        DBG_PRINTF(DBG_ERROR, "error sql: %s\n", sql_buf);
        return 0;
    }
    res_ptr = mysql_store_result(&g_mysql_con);

    while((sql_row = mysql_fetch_row(res_ptr))) {
        int i = 0;

        enum user_code_type code;
        uint32_t            user_id;
        char                user_name[USER_NAME_MAX_LEN + 1];
        char                password[PASSWORD_MAX_LEN + 1];
        char                domain[DOMAIN_MAX_LEN + 1];
        uint32_t            start_time;
        uint32_t            end_time;
        uint64_t            total_flow;
        uint64_t            used_flow;
        uint32_t            del_flag;
        time_t              time;

        user_id             = atoi(sql_row[i++]);
        strncpy(user_name,  sql_row[i++], USER_NAME_MAX_LEN);
        user_name[USER_NAME_MAX_LEN] = 0;
        strncpy(password,  sql_row[i++], PASSWORD_MAX_LEN);
        user_name[PASSWORD_MAX_LEN] = 0;
        strncpy(domain,  sql_row[i++], DOMAIN_MAX_LEN);
        domain[DOMAIN_MAX_LEN] = 0;
        start_time          = atoi(sql_row[i++]);
        end_time            = atoi(sql_row[i++]);
        total_flow          = str_to_u64_base10(sql_row[i++]);
        used_flow           = str_to_u64_base10(sql_row[i++]);
        del_flag            = atoi(sql_row[i++]);
        time                = atoi(sql_row[i++]);

        user_add_account_to_table(&code,
                user_id,
                user_name,
                password,
                domain,
                start_time,
                end_time,
                del_flag,
                total_flow,
                used_flow,
                time);
    }
    mysql_free_result(res_ptr);

    return 0;
}

int dc_mysql_update_domain_list_table()
{
    char sql_buf[MYSQL_BUF_LEN];
    int  ret = 0;
    MYSQL_RES *res_ptr;
    MYSQL_ROW sql_row;

    snprintf(sql_buf, MYSQL_BUF_LEN, "SELECT %s FROM `%s`.`%s`", 
            g_mysql_crossnet_select_column_str[MYSQL_CROSSNET_TABLE_NAME_DOMAIN_LIST],
            g_mysql_db_name[MYSQL_DB_NAME_CROSSNET],
            g_mysql_crossnet_table_name[MYSQL_CROSSNET_TABLE_NAME_DOMAIN_LIST]);

    ret = dc_mysql_real_execute(sql_buf);    
    if (0 != ret) {
        DBG_PRINTF(DBG_ERROR, "error sql: %s\n", sql_buf);
        return 0;
    }
    res_ptr = mysql_use_result(&g_mysql_con);

    domain_map_wrlock();

    domain_map_mark();
    while((sql_row = mysql_fetch_row(res_ptr))) {
        int i = 0;

        struct domain_node domain_node;

        domain_node.user_id             = atoi(sql_row[i++]);
        strncpy(domain_node.domain,  sql_row[i++], DOMAIN_MAX_LEN);
        domain_node.domain[DOMAIN_MAX_LEN] = 0;
        domain_node.used_flow           = str_to_u64_base10(sql_row[i++]);
        domain_node.backend_id = 0;
        domain_node.ip = 0;

        int ret = domain_map_insert_or_update(&domain_node);
        if (ret != SUCCESS) {
            DBG_PRINTF(DBG_WARNING, "update domain %s user_id %u backend_id %u, failed\n",
                    domain_node.domain,
                    domain_node.user_id,
                    domain_node.backend_id);
        }
    }
    domain_map_del();

    domain_map_unlock();

    mysql_free_result(res_ptr);

    return 0;
}

void dc_mysql_enqueue_store_list(struct mysql_store_node *p_node)
{
    struct mysql_manage_table *p_table = &g_mysql_table;

    dc_mysql_lock();
    list_add_tail(&p_node->list_head, &p_table->store_list.list_head);
    p_table->store_list.num++;
    dc_mysql_unlock();
}

struct mysql_store_node *dc_mysql_dequeue_store_list()
{
    struct mysql_manage_table *p_table = &g_mysql_table;
    struct mysql_store_node *p_node = NULL;

    if (p_table->store_list.num > 0) {
        dc_mysql_lock();
        if (!list_empty(&p_table->store_list.list_head)) {
            struct list_head *p_head_node = p_table->store_list.list_head.next;
            p_node = list_entry(p_head_node, struct mysql_store_node, list_head);
            list_del(&p_node->list_head);
            p_table->store_list.num--;
        }
        dc_mysql_unlock();
    }

    return p_node;
}

int dc_mysql_real_store_account(const MYSQL_STORE_ACCOUNT_NODE_T *p_entry)
{    
    char sql_buf[MYSQL_BUF_LEN];

    snprintf(sql_buf, MYSQL_BUF_LEN, g_mysql_crossnet_insert_head_format_str[MYSQL_STORE_TYPE_ACCOUNT], 
            g_mysql_db_name[MYSQL_DB_NAME_CROSSNET],
            g_mysql_crossnet_table_name[MYSQL_CROSSNET_TABLE_NAME_ACCOUNT],
            g_mysql_crossnet_insert_column_str[MYSQL_CROSSNET_TABLE_NAME_ACCOUNT],
            p_entry->user_id,
            p_entry->user_name,
            p_entry->password,
            p_entry->domain,
            p_entry->start_time,
            p_entry->end_time,
            p_entry->total_flow,
            p_entry->used_flow,
            p_entry->del_flag,
            p_entry->time,
            g_mysql_crossnet_insert_tail_format_str[MYSQL_CROSSNET_TABLE_NAME_ACCOUNT]
            );

    //DBG_PRINTF(DBG_WARNING,"%s\n", sql_buf);
    dc_mysql_real_execute(sql_buf);

    return 0;
}

int dc_mysql_real_store(struct mysql_store_node *p_node)
{
    switch(p_node->type) {
        case MYSQL_STORE_TYPE_ACCOUNT:
            dc_mysql_real_store_account(&p_node->data.account);
            break;

        default:
            break;
    }
    return 0;
}

int dc_mysql_store_account(struct user_node *p_user)
{
    struct mysql_store_node *p_node = malloc_mysql_store_node();

    if (p_node == NULL) {
        DBG_PRINTF(DBG_WARNING, "drop\n");
        return -1;
    }
    
    p_node->type = MYSQL_STORE_TYPE_ACCOUNT;
    MYSQL_STORE_ACCOUNT_NODE_T *p_data = &p_node->data.account;
    memcpy(p_data, p_user, sizeof(struct user_node));
    
    dc_mysql_enqueue_store_list(p_node);
    return 0;
}

void *mysql_process(void *arg)
{
    prctl( PR_SET_NAME, __FUNCTION__);

    DBG_PRINTF(DBG_WARNING, "enter\n");

    while(g_main_running) {
        struct mysql_store_node *p_node = dc_mysql_dequeue_store_list();
        if (p_node) {
            dc_mysql_real_store(p_node);
        } else {
            sleep(3);
        }
    }

    DBG_PRINTF(DBG_WARNING, "leave\n");

    exit(EXIT_SUCCESS);
}

int dc_mysql_init()
{
    struct mysql_manage_table *p_table = &g_mysql_table;

    pthread_mutex_init(&p_table->mutex, NULL);

    INIT_LIST_HEAD(&p_table->store_list.list_head);
    p_table->store_list.num = 0;

    mysql_store_buf_table_init();

    if (-1 == dc_mysql_connect_init()) {
        exit(EXIT_SUCCESS);
        return -1;
    }

    dc_mysql_charset_init();
    dc_mysql_db_init();
    dc_mysql_table_init();

    dc_mysql_update_account_table();
    dc_mysql_update_domain_list_table();
    return 0;
}
