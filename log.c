#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <syslog.h>

#include "log.h"


static int  g_file_size        = 0;
static char g_log_path[200]    = {0};
static char *p_g_log_path      = NULL;

void log_init(char *log_path)
{
    g_file_size = 0;

    if (!log_path || log_path[0] == 0)
        p_g_log_path = NULL;
    else {
        strncpy(g_log_path, log_path, sizeof(g_log_path) - 1);
        p_g_log_path = g_log_path;
    }
}

int io_write_time( FILE* fd )
{
    char            tmpbuf[128] = { 0 };
    struct timeval  tv;

    gettimeofday( &tv, NULL );

    time_t timer = tv.tv_sec;
    struct tm* tblock = localtime( &timer );
    int len = sprintf( tmpbuf, "%02d-%02d %02d:%02d:%02d:%03d  ",
                tblock->tm_mon + 1, tblock->tm_mday, tblock->tm_hour,
                tblock->tm_min, tblock->tm_sec, (int)( tv.tv_usec ) / 1000 );

    fwrite( tmpbuf, sizeof( char ), len, fd );

    return len;
}

void io_rotate_log_file()
{
    if (!p_g_log_path)
        return;

    struct timeval tv;
    char           tmpbuf[128] = { 0 };

    gettimeofday(&tv, NULL);

    time_t timer = tv.tv_sec;
    struct tm* tblock = localtime(&timer);
    sprintf(tmpbuf, "%s-%04d%02d%02d%02d%02d%02d", p_g_log_path, tblock->tm_year + 1900, tblock->tm_mon + 1, tblock->tm_mday, tblock->tm_hour, tblock->tm_min, tblock->tm_sec);

    rename(p_g_log_path, tmpbuf);
}

void io_dump_hex(const uint8_t *data, int32_t len)
{
    int line      = 0;
    int max_lines = (len + 16) / 16;

    for (line = 0; line < max_lines; line++) {
	    char buf[100] = {0};

        sprintf( buf, "%s%08x  ", buf, line * 16 );

        /* 打印 hex 字符 */
        int i;
        for ( i = line * 16; i < ( 8 + ( line * 16 ) ); i++ )
        {
            if ( i < len )
            {
                sprintf( buf, "%s%02x ", buf, data[i] );
            }
            else
            {
                sprintf( buf, "%s   ", buf);
            }
        }

        sprintf( buf, "%s ", buf);
        for ( i = ( line * 16 ) + 8; i < ( 16 + ( line * 16 ) ); i++ )
        {
            if ( i < len )
            {
                sprintf( buf, "%s%02x ", buf, data[i] );
            }
            else
            {
                sprintf( buf, "%s   " ,buf);
            }
        }

        sprintf( buf, "%s " ,buf);

        /* 打印ascii字符 */
        for ( i = line * 16; i < ( 8 + ( line * 16 ) ); i++ )
        {
            if ( i < len )
            {
                if ( 32 <= data[i] && data[i] <= 126 )
                {
                    sprintf( buf, "%s%c", buf, data[i] );
                }
                else
                {
                    sprintf( buf, "%s." ,buf);
                }
            }
            else
            {
                sprintf( buf, "%s ", buf);
            }
        }

        sprintf( buf, "%s ", buf);
        for ( i = ( line * 16 ) + 8; i < ( 16 + ( line * 16 ) ); i++ )
        {
            if ( i < len )
            {
                if ( 32 <= data[i] && data[i] <= 126 )
                {
                    sprintf( buf, "%s%c", buf, data[i] );
                }
                else
                {
                    sprintf( buf, "%s.", buf);
                }
            }
            else
            {
                sprintf( buf, "%s ", buf);
            }
        }

        io_printf2("%s\n", buf);
    }
}

/*
 * 文件不要频繁打开关闭
 *
 * */
void io_printf(const char* func, int line, const char* fmt, ...)
{
    if (!p_g_log_path)
        return;

    char        tunnelBuf[LOG_BUF_MAX_SIZE + 1] = {0};
    int         len             = 0;
	va_list     varg;
    FILE*       fd              = NULL;
    int         ret             = 0;
	const char  *log_path       = p_g_log_path;

	len = snprintf(tunnelBuf, LOG_BUF_MAX_SIZE, "[%s %d] ", func, line);

	va_start(varg, fmt);
	ret = vsnprintf(tunnelBuf + len, LOG_BUF_MAX_SIZE - len, fmt, varg);
	va_end( varg );

    if (ret > -1) {
        len += ret;
        if (len > LOG_BUF_MAX_SIZE)
            len = LOG_BUF_MAX_SIZE;
    } else {
	    len += sprintf( tunnelBuf + len, "ret: %d, errno: %d", ret, errno );
    }

    tunnelBuf[len] = 0;

    fd = fopen( log_path, "at+" );
    if (!fd)
        return;

	if(!g_file_size) {
        struct stat file_stat;
        stat(log_path, &file_stat);
        g_file_size += file_stat.st_size;
	}

    ret = io_write_time(fd);
    g_file_size += ret;

    ret = fwrite(tunnelBuf, sizeof(char), len, fd);
    fclose(fd);
    g_file_size += ret;
    if (g_file_size >= LOG_FILE_MAX_SIZE) {
        g_file_size = 0;
		io_rotate_log_file();
        syslog( LOG_INFO, "%s, remove %s \n", __FUNCTION__, log_path);
    }
    return;
}

void io_printf2(const char* fmt, ... )
{
    if (!p_g_log_path)
        return;
    char        tunnelBuf[LOG_BUF_MAX_SIZE + 1] = { 0 };
    int         len             = 0;
    va_list     varg;
    FILE*       fd              = NULL;
    int         ret             = 0;
	const char  *log_path       = p_g_log_path;

    va_start( varg, fmt );
    len = vsnprintf( tunnelBuf, LOG_BUF_MAX_SIZE, fmt, varg );
    va_end( varg );

    fd = fopen( log_path, "at+" );
    if ( !fd )
    {
        return;
    }

    if( !g_file_size )
    {
        struct stat file_stat;
        stat( log_path, &file_stat);
        g_file_size += file_stat.st_size;
    }

    ret = fwrite( tunnelBuf, sizeof( char ), len, fd );
    fclose( fd );
    g_file_size += ret;

    if ( g_file_size >= LOG_FILE_MAX_SIZE )
    {
		io_rotate_log_file();
        syslog( LOG_INFO, "%s, remove %s \n", __FUNCTION__, log_path);
        g_file_size = 0;
    }
    return;
}

