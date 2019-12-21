#ifndef _MAIN_H
#define _MAIN_H

enum debug_level
{
	DEBUG_CLOSE,  /* 0 */
	DEBUG_ERROR,  /* 1 */
	DEBUG_WARNING,/* 2 */
    DEBUG_NORMAL, /* 3 */
    DEBUG_MAX,
};  


#define BACKEND_PORT   66 
extern int g_main_running;
#endif
