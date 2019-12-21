#ifndef _LOG_H_
#define _LOG_H_

#include <stdbool.h>
#include <stdint.h>

#define LOG_FILE_MAX_SIZE          (1024 * 1024 * 500)
#define LOG_BUF_MAX_SIZE          (1024 * 8)

void log_init(char *log_path);
void log_dump_hex(const uint8_t *data, int32_t len);
extern void io_printf( const char* func, int line, const char* fmt, ... );
extern void io_printf2( const char* fmt, ... );

extern int   g_main_debug;


#define DBG_PRINTF(debug_level, fmt...) \
{ \
    if (debug_level <= g_main_debug) \
        io_printf( __FUNCTION__, __LINE__, fmt);\
}


#define DBG_RAW_PRINTF(fmt...)  io_printf2(fmt);

#endif

