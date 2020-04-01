//#define _GNU_SOURCE
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
#include <json-c/json.h>

#include "main.h"
#include "log.h"
#include "frontend.h"
#include "backend.h"
#include "unique_id.h"
#include "heaptimer.h"
#include "dc_mysql.h"
#include "user.h"
#include "domain_map.h"

struct ctx g_ctx;

int g_main_running = 1;
int g_main_debug = DBG_NORMAL;

void *timer_process(void *arg)
{
    prctl(PR_SET_NAME, __FUNCTION__);

    DBG_PRINTF(DBG_WARNING, "enter timerstamp %d\n", time(NULL));

    while(g_main_running) {
        sleep(20);
    }

    DBG_PRINTF(DBG_WARNING, "leave timestamp %d\n", time(NULL));

    exit(EXIT_SUCCESS);
}

int main_daemon()
{
    switch (fork()) {
    case -1:
        DBG_PRINTF(DBG_ERROR, "fork() failed");
        return -1;

    case 0:
        break;

    default:
        exit(0);
    }

    if (setsid() == -1) {
        DBG_PRINTF(DBG_ERROR, "setsid() failed");
        return -1;
    }

    umask(0);

    int fd = open("/dev/null", O_RDWR);
    if (fd == -1) {
        DBG_PRINTF(DBG_ERROR, "open(\"/dev/null\") failed");
        return -1;
    }

    if (dup2(fd, STDIN_FILENO) == -1) {
        DBG_PRINTF(DBG_ERROR, "dup2(STDIN) failed");
        return -1;
    }

    if (dup2(fd, STDOUT_FILENO) == -1) {
        DBG_PRINTF(DBG_ERROR, "dup2(STDOUT) failed");
        return -1;
    }

    if (fd > STDERR_FILENO) {
        if (close(fd) == -1) {
            DBG_PRINTF(DBG_ERROR, "close() failed");
            return -1;
        }
    }

    return 0;
}

/* Signale wrapper. */
void signal_set(int signo, void (*func)(int))
{
    struct sigaction sig;
    struct sigaction osig;

    sig.sa_handler = func;
    sig.sa_flags = 0;
#ifdef SA_RESTART
    sig.sa_flags |= SA_RESTART;
#endif /* SA_RESTART */

    if ((-1 == sigemptyset (&sig.sa_mask))
            || (-1 == sigaction (signo, &sig, &osig))) {
        DBG_PRINTF(DBG_CLOSE, "signal %d, error\n", signo);
        perror("failed to set signal\n");
        exit(EXIT_FAILURE);
    }
}

void sigfun(int sig)
{
    DBG_PRINTF(DBG_CLOSE, "signal %d\n", sig);
    signal_set(sig, SIG_DFL);
    g_main_running = 0;
}

void signal_init ()
{
    //signal_set (SIGINT, sigfun);
    signal_set (SIGTSTP, sigfun);
    //signal_set (SIGKILL, sigfun);
    //signal_set (SIGTERM, sigfun);
    signal_set (SIGSEGV, sigfun);
}

int init()
{
    signal_init();

    unique_id_init();
    notify_buf_table_init();

    domain_map_table_init();
    user_table_init();
    dc_mysql_init();

    frontend_init();
    backend_init();

    return 0;
}

int parse_json_config(char *config_str)
{
    int ret = SUCCESS;
    struct ctx *p_ctx = &g_ctx;

    json_object *obj = json_tokener_parse(config_str);
    if (!obj) {   
        printf("json_parse_error\n");
        ret = FAIL;
        goto JSON_ERROR_END;
    }

    json_type type = json_object_get_type(obj);
    if(type != json_type_object) {   
        printf("json_type: %d\n", type);
        ret = FAIL;
        goto JSON_ERROR_END;
    }

    json_object_object_foreach(obj, key, val) {   
        json_type type =json_object_get_type(val);

        if (strcmp(key, "mysql_name") == 0) {   
            if(type == json_type_string) {
                snprintf(p_ctx->mysql_name, USER_NAME_MAX_LEN + 1, "%s", json_object_get_string(val));
                p_ctx->mysql_name[USER_NAME_MAX_LEN] = 0;
            } else {
                ret = FAIL;
                goto JSON_ERROR_END;
            }
        } else if (strcmp(key, "mysql_pass") == 0) {   
            if(type == json_type_string) {
                snprintf(p_ctx->mysql_pass, PASSWORD_MAX_LEN + 1, "%s", json_object_get_string(val));
                p_ctx->mysql_pass[PASSWORD_MAX_LEN] = 0;
            } else {
                ret = FAIL;
                goto JSON_ERROR_END;
            }
        } else if (strcmp(key, "mysql_port") == 0) {   
            if(type == json_type_int) {
                p_ctx->mysql_port = json_object_get_int(val);
            } else {
                ret = FAIL;
                goto JSON_ERROR_END;
            }
        } else if (strcmp(key, "debug_level") == 0) {   
            if(type == json_type_int) {
                p_ctx->debug_level = json_object_get_int(val);
            } else {
                ret = FAIL;
                goto JSON_ERROR_END;
            }
        } else if (strcmp(key, "log_file") == 0) {   
            if(type == json_type_string) {
                snprintf(p_ctx->log_file, LOG_FILE_NAME_MAX_LEN + 1, "%s", json_object_get_string(val));
                p_ctx->log_file[LOG_FILE_NAME_MAX_LEN] = 0;
            } else {
                ret = FAIL;
                goto JSON_ERROR_END;
            }
        } else {
            printf("unknown json key: %s\n", key);
        }
    }

JSON_ERROR_END:
    json_object_put(obj);

    return ret;
}

int check_and_print_ctx()
{
    struct ctx *p_ctx = &g_ctx;

    if (!p_ctx->mysql_name[0]) {
        printf("user_name should not be empty!\n");
        return FAIL;
    }
    if (!p_ctx->mysql_pass[0]) {
        printf("mysql_pass should not be empty!\n");
        return FAIL;
    }
    if (p_ctx->mysql_port < 1) {
        printf("mysql_port should not be zero!\n");
        return FAIL;
    }
    g_main_debug = p_ctx->debug_level;

    printf("config success!\n");
    printf("mysql_name: %s\n", p_ctx->mysql_name);
    printf("mysql_pass: %s\n", p_ctx->mysql_pass);
    printf("mysql_port: %hu\n", p_ctx->mysql_port);
    printf("debug_level: %d\n", p_ctx->debug_level);
    printf("log_file: %s\n", p_ctx->log_file);

    return SUCCESS;
}

int load_config_from_json_file(char *config)
{
    FILE  *fp        = NULL;
    char buffer[2048] = {0};
    int ret = 0;

    if (config == NULL) {
        printf("config file not found!\n");
        return FAIL;
    }

    if (NULL == (fp = fopen(config, "r"))) {
        printf("open %s failed!\n", config);
        return FAIL;
    }

    ret = fread(buffer, 1, 2048, fp);
    if (ret <= 0) {
        printf("config file %s empty!\n", config);
        return FAIL;
    }
    if (ret >= 2048) {
        printf("config file %s too big!\n", config);
        return FAIL;
    }

    //printf("%d\n", ret);
    //printf("%s\n", buffer);
    return parse_json_config(buffer);
}

int main(int argc, char **argv)
{
    bool daemon = false;
    char *config = "config.json";

    //test_heap_timer();
    //return 0;
    int c, option_index;
    static struct option long_options[] = {
        {"daemon",  no_argument,        NULL,   'd'},
        {"config",  required_argument,  NULL,   'c'},
        {"version", no_argument,        NULL,   'v'},
        {NULL,      0,                  NULL,   0}
    };

    while (-1 != (c = getopt_long(argc, argv, "dc:v", long_options, &option_index))) {
        switch (c) {
        case 'd':
            daemon = true;
            break;

        case 'c':
            config = optarg;
            (void)config;
            //printf("config %s\n", config);
            break;

        case 'v':
            printf("%s\n", VERSION);
            exit(0);
            break;

        default:
            printf("?? getopt returned character code 0%o ??\n", c);
            exit(EXIT_FAILURE);
        }
    }

    memset(&g_ctx, 0, sizeof(struct ctx));
    g_ctx.debug_level = DBG_NORMAL;

    if (FAIL == load_config_from_json_file(config)) {
        exit(EXIT_FAILURE);
    }

    if (FAIL == check_and_print_ctx()) {
        exit(EXIT_FAILURE);
    }

    log_init(g_ctx.log_file);

    if (daemon) {
        main_daemon();
    }

    //display_g_main_config();

    init();

#if 0
    setvbuf(stdout,NULL,_IONBF,0);
#endif

    int res;
    pthread_t frontend_thread;
    pthread_t backend_thread;
    pthread_t timer_thread;
    pthread_t user_socket_thread;
    pthread_t mysql_thread;

    sigset_t signal_mask;
    sigemptyset(&signal_mask);
    sigaddset(&signal_mask, SIGPIPE);
    int rc = pthread_sigmask (SIG_BLOCK, &signal_mask, NULL);
    if (rc != 0) {
        printf("block sigpipe error\n");
    }

    res = pthread_create(&frontend_thread, NULL, frontend_accept_process, NULL);
    if (res != 0) {
        perror("Thread creation failed!");
        exit(EXIT_FAILURE);
    }

    res = pthread_create(&backend_thread, NULL, backend_accept_process, NULL);
    if (res != 0) {
        perror("Thread creation failed!");
        exit(EXIT_FAILURE);
    }

    res = pthread_create(&timer_thread, NULL, timer_process, NULL);
    if (res != 0) {
        perror("Thread creation failed!");
        exit(EXIT_FAILURE);
    }

    res = pthread_create(&user_socket_thread, NULL, user_socket_process, NULL);
    if (res != 0) {
        perror("Thread creation failed!");
        exit(EXIT_FAILURE);
    }

    res = pthread_create(&mysql_thread, NULL, mysql_process, NULL);
    if (res != 0) {
        perror("Thread creation failed!");
        exit(EXIT_FAILURE);
    }

    res = pthread_join(frontend_thread, NULL);
    if (res != 0) {
        perror("Thread join failed!");
        exit(EXIT_FAILURE);
    }

    res = pthread_join(backend_thread, NULL);
    if (res != 0) {
        perror("Thread join failed!");
        exit(EXIT_FAILURE);
    }

    res = pthread_join(timer_thread, NULL);
    if (res != 0) {
        perror("Thread join failed!");
        exit(EXIT_FAILURE);
    }

    res = pthread_join(user_socket_thread, NULL);
    if (res != 0) {
        perror("Thread join failed!");
        exit(EXIT_FAILURE);
    }

    res = pthread_join(mysql_thread, NULL);
    if (res != 0) {
        perror("Thread join failed!");
        exit(EXIT_FAILURE);
    }

    return 0;
}
