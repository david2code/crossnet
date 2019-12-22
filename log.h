#ifndef _LOG_H_
#define _LOG_H_

#include <stdbool.h>
#include <stdint.h>

#define LOG_FILE_MAX_SIZE          (1024 * 1024 * 500)
#define LOG_BUF_MAX_SIZE          (1024 * 8)

enum dbg_level {
	DBG_CLOSE,  /* 0 */
	DBG_ERROR,  /* 1 */
	DBG_WARNING,/* 2 */
    DBG_NORMAL, /* 3 */
    DBG_MAX,
};

void log_init(char *log_path);
void log_dump_hex(const uint8_t *data, int32_t len);
extern void io_printf(const char *dbg_str, const char* func, int line, const char* fmt, ...);
extern void io_printf2(const char* fmt, ...);

extern int g_main_debug;

extern const char *g_dbg_level_str[DBG_MAX];

#define DBG_PRINTF(dbg_level, fmt...) { \
    if (dbg_level <= g_main_debug) \
        io_printf(g_dbg_level_str[dbg_level],  __FUNCTION__, __LINE__, fmt);\
}

#define DBG_RAW_PRINTF(fmt...)  io_printf2(fmt);

#endif

