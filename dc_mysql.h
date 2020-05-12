#ifndef _DC_MYSQL_H
#define _DC_MYSQL_H
#include "user.h"


#define MYSQL_EXECUTE_MAX_TRY_NUM 3
#define MYSQL_BUF_LEN  2048


enum {
    MYSQL_DB_NAME_CROSSNET,
    MYSQL_DB_NAME_CROSSNET_LOG,
    MYSQL_DB_NAME_MAX
};

enum {
    MYSQL_CROSSNET_TABLE_NAME_ACCOUNT,
    MYSQL_CROSSNET_TABLE_NAME_DOMAIN_LIST,
    MYSQL_CROSSNET_TABLE_NAME_RECORD,
    MYSQL_CROSSNET_TABLE_NAME_MAX
};

enum mysql_store_type {
    MYSQL_STORE_TYPE_ACCOUNT,
    MYSQL_STORE_TYPE_MAX
};

typedef struct user_node  MYSQL_STORE_ACCOUNT_NODE_T;

struct mysql_store_node {
    struct list_head            list_head;
    enum mysql_store_type       type;

    union {
        MYSQL_STORE_ACCOUNT_NODE_T  account;
    } data;
};

struct mysql_manage_table {
    //MYSQL                           con;

    pthread_mutex_t                 mutex;
    struct list_table               store_list;
};

int dc_mysql_init();
int dc_mysql_update_ip_location();
void *mysql_process(void *arg);

int dc_mysql_store_account(struct user_node *p_user);
#endif
