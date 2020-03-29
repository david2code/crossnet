#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>

#include <sys/msg.h>
#include <netinet/tcp.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <netdb.h>
extern int h_errno;
#include <net/if.h>

#include <zlib.h>
#include <assert.h>
#include <sys/ioctl.h>
#include <iconv.h>

#include "misc.h"

/*

功能: 根据主机名返回ip班机字节序的ip地址
*/
uint32_t get_ip_by_hostname(const char *hostname)
{
    if (!hostname)
        return 0;
    
    struct hostent* hostent = gethostbyname(hostname);

    if (hostent == NULL)
    {
        return 0;
    }
    else
    {
        return ntohl(*(uint32_t *)hostent->h_addr);
    }
}

#if 1  
/*
*实现对字符串进行计算hash操作
*摘抄自: http://blog.csdn.net/qisefengzheng/article/details/51034151
*/
#define __jhash_mix(a, b, c) \
{ \
  a -= b; a -= c; a ^= (c>>13); \
  b -= c; b -= a; b ^= (a<<8); \
  c -= a; c -= b; c ^= (b>>13); \
  a -= b; a -= c; a ^= (c>>12);  \
  b -= c; b -= a; b ^= (a<<16); \
  c -= a; c -= b; c ^= (b>>5); \
  a -= b; a -= c; a ^= (c>>3);  \
  b -= c; b -= a; b ^= (a<<10); \
  c -= a; c -= b; c ^= (b>>15); \
}

/* The golden ration: an arbitrary value */
#define JHASH_GOLDEN_RATIO	0x9e3779b9

uint32_t jhash(const void *key, uint32_t length, uint32_t initval)
{
    if (!key)
        return 0;
    
    uint32_t a, b, c, len;
    const uint8_t *k = ( uint8_t* )key;

    len = length;
    a = b = JHASH_GOLDEN_RATIO;
    c = initval;

    while (len >= 12) {
         a += (k[0] +((uint32_t)k[1]<<8) +((uint32_t)k[2]<<16) +((uint32_t)k[3]<<24));
         b += (k[4] +((uint32_t)k[5]<<8) +((uint32_t)k[6]<<16) +((uint32_t)k[7]<<24));
         c += (k[8] +((uint32_t)k[9]<<8) +((uint32_t)k[10]<<16)+((uint32_t)k[11]<<24));

        __jhash_mix(a,b,c);

        k += 12;
        len -= 12;
    }

    c += length;
    switch (len) {
    case 11: c += ((uint32_t)k[10]<<24);
    case 10: c += ((uint32_t)k[9]<<16);
    case 9 : c += ((uint32_t)k[8]<<8);
    case 8 : b += ((uint32_t)k[7]<<24);
    case 7 : b += ((uint32_t)k[6]<<16);
    case 6 : b += ((uint32_t)k[5]<<8);
    case 5 : b += k[4];
    case 4 : a += ((uint32_t)k[3]<<24);
    case 3 : a += ((uint32_t)k[2]<<16);
    case 2 : a += ((uint32_t)k[1]<<8);
    case 1 : a += k[0];
    };

    __jhash_mix(a,b,c);

    return c;
}

#endif

#if 1
/*
创建一个监听套接字
返回值 
*/
int create_listen_socket_process(uint32_t ip, uint16_t port, int back_log, bool nodelay)
{
    //设置一个socket地址结构server_addr,代表服务器internet地址, 端口
    struct sockaddr_in server_addr;
    bzero(&server_addr,sizeof(server_addr)); //把一段内存区的内容全部设置为0
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(ip);
    server_addr.sin_port = htons(port);
 
    //创建用于internet的流协议(TCP)socket,用server_socket代表服务器socket
    int server_socket = socket(PF_INET,SOCK_STREAM,0);
    if( server_socket < 0)
        return -1;

    int opt = 1;
    setsockopt(server_socket,SOL_SOCKET,SO_REUSEADDR,&opt,sizeof(opt));
    if (nodelay) {
        opt = 1;
        setsockopt(server_socket, IPPROTO_TCP, TCP_NODELAY, (char *)&opt, sizeof(opt));
    }
     
    //把socket和socket地址结构联系起来
    if( bind(server_socket,(struct sockaddr*)&server_addr,sizeof(server_addr)))
        return -2;
 
    //server_socket用于监听
    if (0 != listen(server_socket, back_log)) {
        return -3;
    }
    
    return server_socket;
}


int create_listen_socket(uint16_t port, int back_log)
{
    return create_listen_socket_process(INADDR_ANY, port, back_log, false);
}

int create_listen_socket_at_address(uint32_t ip, uint16_t port, int back_log)
{
    return create_listen_socket_process(ip, port, back_log, false);
}
int create_listen_socket_nodelay(uint16_t port, int back_log)
{
    return create_listen_socket_process(INADDR_ANY, port, back_log, true);
}
/*
创建一个udp监听套接字
返回值 
*/
int create_udp_listen_socket(uint16_t *port)
{
    int sockfd;
    struct sockaddr_in server_addr;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if( sockfd < 0)
    {
        return -1;
    }
    
    bzero(&server_addr,sizeof(server_addr)); //把一段内存区的内容全部设置为0
    server_addr.sin_family      = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port        = htons(*port);
 

   int opt = 1;
   setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
     
    //把socket和socket地址结构联系起来
    if( bind(sockfd,(struct sockaddr*)&server_addr,sizeof(server_addr)))
    {
        close(sockfd);
        return -2;
    }

    socklen_t len = sizeof(server_addr);
    if (getsockname(sockfd, (struct sockaddr *)&server_addr, &len) == -1)
    {
        close(sockfd);
        return -3;
    }

    *port = ntohs(server_addr.sin_port);
    
    return sockfd;
}

/*
* epoll的设置基本操作函数
* 摘抄自  https://github.com/yedf/handy/blob/master/raw-examples/epoll-et.cc
*/
int set_none_block(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0)
    {
        return -1;
    }
    
    int r = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    if (r < 0)
    {
        return -1;
    }

    return 0;
}

void add_event(int epollfd, int fd, void *ptr, int state)
{    
    struct epoll_event ev;
    ev.events = state;
    ev.data.ptr = ptr;
    epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &ev);
}

void delete_event(int epollfd, int fd, void *ptr, int state)
{
    struct epoll_event ev;
    ev.events = state;
    ev.data.ptr = ptr;
    epoll_ctl(epollfd, EPOLL_CTL_DEL, fd, &ev);
}

void modify_event(int epollfd,int fd, void *ptr, int state)
{
    struct epoll_event ev;
    ev.events = state;
    ev.data.ptr = ptr;
    epoll_ctl(epollfd, EPOLL_CTL_MOD, fd, &ev);
}

#endif

#if 1
/*
*功能 创建一个连接ip+port地址的socket,超时时间为connect_timeout
*返回值  -1 创建socket失败
*        -2 连接超时
*/
int create_socket_to_server(uint32_t ip, uint16_t port, int connect_timeout)
{    
    int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd < 0)
    {
        return -1;
    }

    struct sockaddr_in server_addr;
    bzero(&server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(ip);
    server_addr.sin_port = htons(port);

    int opt =1;
    setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt));
    opt = 1;
    setsockopt(socket_fd, IPPROTO_TCP, TCP_NODELAY, (char *)&opt, sizeof(opt));

    set_none_block(socket_fd);

    //通过sleep的方式判断超时
    time_t time_start = time(NULL);
    while(connect(socket_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0)
    {
        if ((time(NULL) - time_start) > connect_timeout)
        {
            close(socket_fd);
            return -2;
        }
        usleep(100000);
    }
    
    return socket_fd;
}

int create_socket_to_server2(char *ip_str, uint16_t port, int connect_timeout)
{
    struct sockaddr_in server_addr;
    inet_aton(ip_str, &server_addr.sin_addr);

    return create_socket_to_server(ntohl(server_addr.sin_addr.s_addr), port, connect_timeout);
}

#endif

#if 1
char *u64_to_mac_str(char *mac, int len, uint64_t mac_u64)
{
    snprintf(mac, len, "%012lX", mac_u64);
    return mac;
}

uint64_t mac_str_to_u64(char *mac)
{
    uint64_t mac_u64 = 0;
    sscanf(mac, "%lx", &mac_u64);
    return mac_u64;
}

uint64_t str_to_u64_base10(char *str)
{
    uint64_t value = 0;
    sscanf(str, "%lu", &value);
    return value;
}

uint32_t str_to_u32_base10(char *str)
{
    uint32_t value = 0;
    sscanf(str, "%u", &value);
    return value;
}

uint16_t str_to_u16_base10(char *str)
{
    uint16_t value = 0;
    sscanf(str, "%hu", &value);
    return value;
}
/*
通过比较两个时间，判断是否是新的一天
*/
bool is_new_day(time_t last_time, time_t now_time)
{
    struct tm tm_now, tm_last;

    localtime_r(&now_time,  &tm_now);
    localtime_r(&last_time, &tm_last);

    if (tm_now.tm_mday != tm_last.tm_mday
        || tm_now.tm_mon != tm_last.tm_mon
        || tm_now.tm_year != tm_last.tm_year)
    {
        return true;
    }

    return false;
}

int get_hour(time_t now_time)
{
    struct tm tm_now;

    localtime_r(&now_time,  &tm_now);
    return tm_now.tm_hour;
}

bool is_new_hour(time_t last_time, time_t now_time)
{
    struct tm tm_now, tm_last;

    localtime_r(&now_time,  &tm_now);
    localtime_r(&last_time, &tm_last);

    if (tm_now.tm_hour != tm_last.tm_hour
        || tm_now.tm_mday != tm_last.tm_mday
        || tm_now.tm_mon != tm_last.tm_mon
        || tm_now.tm_year != tm_last.tm_year)
    {
        return true;
    }

    return false;
}
#endif

tlv_node_t *tlv_node_fill(tlv_node_t *p_tlv, uint8_t type, char *value)
{
    uint16_t length = strlen(value);
    
    p_tlv->type = type;
    p_tlv->length = htons(length);
    memcpy(p_tlv->value, value, length);

    return (tlv_node_t *)(p_tlv->value + length);
}

tlv_node_t *tlv_node_fill_uint8_t(tlv_node_t *p_tlv, uint8_t type, uint8_t value)
{    
    p_tlv->type = type;
    p_tlv->length = htons(sizeof(value));
    *((uint8_t *)p_tlv->value) = value;

    return (tlv_node_t *)(p_tlv->value + sizeof(value));
}

tlv_node_t *tlv_node_fill_uint16_t(tlv_node_t *p_tlv, uint8_t type, uint16_t value)
{    
    p_tlv->type = type;
    p_tlv->length = htons(sizeof(value));
    uint16_t *p = (uint16_t *)p_tlv->value;
    *p = htons(value);

    return (tlv_node_t *)(p_tlv->value + sizeof(value));
}

tlv_node_t *tlv_node_fill_uint32_t(tlv_node_t *p_tlv, uint8_t type, uint32_t value)
{    
    p_tlv->type = type;
    p_tlv->length = htons(sizeof(value));
    uint32_t *p = (uint32_t *)p_tlv->value;
    *p = htonl(value);

    return (tlv_node_t *)(p_tlv->value + sizeof(value));
}

tlv_node_t *tlv_node_fill_uint64_t(tlv_node_t *p_tlv, uint8_t type, uint64_t value)
{    
    p_tlv->type = type;
    p_tlv->length = htons(sizeof(value));
    uint64_t *p = (uint64_t *)p_tlv->value;
    *p = htonll(value);

    return (tlv_node_t *)(p_tlv->value + sizeof(value));
}

tlv_node_t *tlv_node_fill_with_length(tlv_node_t *p_tlv, uint8_t type, uint8_t *value, uint16_t length)
{    
    p_tlv->type = type;
    p_tlv->length = htons(length);
    memcpy(p_tlv->value, value, length);

    return (tlv_node_t *)(p_tlv->value + length);
}

uint8_t * ngx_strnstr(uint8_t *s1, char *s2, size_t len)
{
    uint8_t  c1, c2;
    size_t  n;

    c2 = *(uint8_t *) s2++;

    n = ngx_strlen(s2);

    do {
        do {
            if (len-- == 0) {
                return NULL;
            }

            c1 = *s1++;

            if (c1 == 0) {
                return NULL;
            }

        } while (c1 != c2);

        if (n > len) {
            return NULL;
        }

    } while (ngx_strncmp(s1, (uint8_t *) s2, n) != 0);

    return --s1;
}


/*
 * We use ngx_strcasecmp()/ngx_strncasecmp() for 7-bit ASCII strings only,
 * and implement our own ngx_strcasecmp()/ngx_strncasecmp()
 * to avoid libc locale overhead.  Besides, we use the ngx_uint_t's
 * instead of the uint8_t's, because they are slightly faster.
 */

ngx_int_t ngx_strcasecmp(uint8_t *s1, uint8_t *s2)
{
    ngx_uint_t  c1, c2;

    for ( ;; ) {
        c1 = (ngx_uint_t) *s1++;
        c2 = (ngx_uint_t) *s2++;

        c1 = (c1 >= 'A' && c1 <= 'Z') ? (c1 | 0x20) : c1;
        c2 = (c2 >= 'A' && c2 <= 'Z') ? (c2 | 0x20) : c2;

        if (c1 == c2) {

            if (c1) {
                continue;
            }

            return 0;
        }

        return c1 - c2;
    }
}

ngx_int_t ngx_strncasecmp(uint8_t *s1, uint8_t *s2, size_t n)
{
    ngx_uint_t  c1, c2;

    while (n) {
        c1 = (ngx_uint_t) *s1++;
        c2 = (ngx_uint_t) *s2++;

        c1 = (c1 >= 'A' && c1 <= 'Z') ? (c1 | 0x20) : c1;
        c2 = (c2 >= 'A' && c2 <= 'Z') ? (c2 | 0x20) : c2;

        if (c1 == c2) {

            if (c1) {
                n--;
                continue;
            }

            return 0;
        }

        return c1 - c2;
    }

    return 0;
}

#if 1
int char2value (char ch)
{    
    if ((ch >= '0') && (ch <= '9'))
    {
        return (ch - '0');
    }
    else if ((ch >= 'a') && (ch <= 'z'))
    {
        return (ch - 'a' + 10);
    }
    else if ((ch >= 'A') && (ch <= 'Z'))
    {
        return (ch - 'A' + 10);
    }
    else
    {
        return -1;
    }
}

/*
 * url解码函数
 * 成功返回0
 * 失败返回 -1
 */
int url_str_decode(char *dest, const char *src, int dest_len)
{
    if (!src || !dest || (dest_len < 1))
        return -1;
    
    const char*     p_src       = src;
    char*           p_dest      = dest;
    char*           p_dest_end  = dest + dest_len;
    
    while (*p_src && p_dest < p_dest_end )
    {
        if (*p_src == '%')
        {
            p_src++;
            
            int value = char2value(*p_src++);
            *p_dest++ = (value << 4) + char2value(*p_src++);
        }
        else if (*p_src == '+')
        {
            p_src++;
            *p_dest++ = ' ';
        }
        else
        {
            *p_dest++ = *p_src++;
        }
    }
    *p_dest = 0;

    return 0;
}

/*
 * url解码函数
 * 成功返回0
 * 失败返回 -1
 */
int url_str_decode2(ngx_str_t *p_ngx_dest, ngx_str_t *p_ngx_src)
{
    if (!p_ngx_dest || !p_ngx_src)
        return -1;
    
    char*           p_src       = (char *)p_ngx_src->data;
    char*           p_src_end   = (char *)p_ngx_src->data + p_ngx_src->len;
    char*           p_dest      = (char *)p_ngx_dest->data;
    char*           p_dest_end  = (char *)p_ngx_dest->data + p_ngx_dest->len;
    
    while (p_src < p_src_end && p_dest < p_dest_end )
    {
        if (*p_src == '%')
        {
            p_src++;
            
            int value = char2value(*p_src++);
            *p_dest++ = (value << 4) + char2value(*p_src++);
        }
        else if (*p_src == '+')
        {
            p_src++;
            *p_dest++ = ' ';
        }
        else
        {
            *p_dest++ = *p_src++;
        }
    }
    *p_dest = 0;
    p_ngx_dest->len = p_dest - (char *)p_ngx_dest->data;

    return 0;
}

#endif


#if 1
/*
*将字符串转换为mysql格式
*/
void string_process_for_mysql( char* dstStr, const char* srcStr, int dstLen)
{
    char*         pDst    = dstStr;
    const char*   pSrc    = srcStr;
    char*         pDstEnd = dstStr + dstLen;

    if (dstLen < 1 || !dstStr || !srcStr)
    {
        return ;
    }

    while (*pSrc != '\0' && (pDst < pDstEnd))
    {
        if( *pSrc == '\\'
            || *pSrc == '\''
            || *pSrc == '"' )
        {
            *pDst = '\\';
            pDst++;
            if (pDst == pDstEnd)
                break;
        }

        *pDst = *pSrc;
        pSrc++;
        pDst++;
    }
    *pDst = '\0';
}

#endif

uint8_t *
ngx_strnstrn(uint8_t *s1, uint8_t *s2, size_t len, size_t s2_len)
{
    uint8_t  c1, c2;
    size_t  n;

    c2 = *(uint8_t *) s2++;

    n = s2_len - 1;

    do {
        do {
            if (len-- == 0) {
                return NULL;
            }

            c1 = *s1++;

            if (c1 == 0) {
                return NULL;
            }

        } while (c1 != c2);

        if (n > len) {
            return NULL;
        }

    } while (ngx_strncmp(s1, (uint8_t *) s2, n) != 0);

    return --s1;
}

/*
去掉字符串中的所有空格
*/
void trim_space(ngx_str_t *str)
{
    assert(str);
    
    uint8_t *pos = str->data;
    uint8_t *start = str->data;
    uint8_t *end = pos + str->len;

    while(pos < end)
    {
        if (!isspace(*pos))
        {
            *start = *pos;
            start++;
        }

        pos++;
    }

    str->len = start - str->data;
}

int get_middle_str(const ngx_str_t *str, const ngx_str_t *left, const ngx_str_t *right, ngx_str_t *mid)
{
    assert(str);assert(left);assert(right);assert(mid);
    
    uint8_t *mid_start = ngx_strnstrn(str->data, left->data, str->len, left->len);
    if (mid_start == NULL)
        return -1;

    mid_start += left->len;

    
    uint8_t *mid_end = ngx_strnstrn(mid_start, right->data, str->data + str->len - mid_start, right->len);
    if (mid_end == NULL)
        return -1;

    mid->data = mid_start;
    mid->len = mid_end - mid_start;

    return 0;
}



int uri_parse(ngx_str_t *uri, ngx_str_t *host, ngx_str_t *url)
{
    assert(uri);
    assert(host);
    assert(url);
    
    ngx_str_t left = ngx_string("http://");
    ngx_str_t right = ngx_string("/");

    ngx_str_null(host);
    ngx_str_null(url);
    if (0 == get_middle_str(uri, &left, &right, host))
    {
        url->data = host->data + host->len;
        url->len = uri->data + uri->len - url->data;
        return 0;
    }
    else
    {
        return -1;
    }
}

/*
从host中取出端口号
默认为 80
*/
uint16_t get_port_from_host(const char *host)
{
    assert(host);
    
    char *pos = strchr(host, ':');
    if (pos)
    {
        *pos = 0;
        return atoi(pos + 1);
    }
    else
    {
        return 80;
    }
}

int check_is_process_alive(const char *proc_name)
{
    int ret = 0;
    char command[100];
    
    snprintf(command, sizeof(command) - 1, "ps -ef|grep %s|grep -v grep", proc_name);
    
    FILE *fp = popen( command,"r" );
    if (!fp)
        return -1;

    char buf[200];
    if (NULL != fgets(buf, sizeof(buf), fp)) {
        //printf("%s\n", buf);
    } else {
        ret = -1;
    }

    pclose(fp);
    return ret;
}

uint64_t get_eth_mac(const char *eth_name)
{
    int sock = 0;
    uint64_t mac = 0;

    sock = socket(AF_INET,SOCK_STREAM,0);
    if(sock < 0)
    {
        perror("error sock");
        return mac;
    }

    struct ifreq ifreq;
    strcpy(ifreq.ifr_name, eth_name);
    if(ioctl(sock,SIOCGIFHWADDR,&ifreq) < 0)
    {
        perror("error ioctl");
        return mac;
    }

    int i = 0;
    for(i = 0; i < 6; i++){
        mac = (mac << 8) + (uint8_t)ifreq.ifr_hwaddr.sa_data[i];
    }
                
    return mac;
}

/* host */
uint32_t get_eth_ip(const char *eth_name)
{
    int sock = 0;
    uint32_t ip = 0;

    sock = socket(AF_INET,SOCK_STREAM,0);
    if(sock < 0)
    {
        perror("error sock");
        return ip;
    }

    struct ifreq ifreq;
    strcpy(ifreq.ifr_name, eth_name);
    if(ioctl(sock,SIOCGIFADDR,&ifreq) < 0)
    {
        perror("error ioctl");
        close(sock);
        return ip;
    }

    close(sock);
    ip = ntohl(((struct sockaddr_in *)&ifreq.ifr_addr)->sin_addr.s_addr);
    return ip;
}

uint32_t get_addrinfo(char *host)
{
    uint32_t    addr = 0;
	struct addrinfo *ai = NULL,*pai;
	if (getaddrinfo(host, NULL, NULL, &ai) || !ai) {
		return addr;
	}

	for (pai = ai ; pai ; pai = pai->ai_next) {
		struct sockaddr_in *ptr = (struct sockaddr_in *)pai->ai_addr;
		addr = ptr->sin_addr.s_addr;
		if (addr)
		{
            break;
		}
	}
	freeaddrinfo(ai);
    return ntohl(addr);
}

unsigned long long ntohll(unsigned long long val)
  {
     if (__BYTE_ORDER == __LITTLE_ENDIAN)
      {
         return (((unsigned long long )htonl((int)((val << 32) >> 32))) << 32) | (unsigned int)htonl((int)(val >> 32));
     }
     else if (__BYTE_ORDER == __BIG_ENDIAN)
      {
         return val;
     }
 }

unsigned long long htonll(unsigned long long val)
 {
	if (__BYTE_ORDER == __LITTLE_ENDIAN)
	 {
		return (((unsigned long long )htonl((int)((val << 32) >> 32))) << 32) | (unsigned int)htonl((int)(val >> 32));
	}
	else if (__BYTE_ORDER == __BIG_ENDIAN)
	 {
		return val;
	}
}


inline int uint16_t_cmp(uint16_t *a, uint16_t *b)
{
    return (*a == *b) ? 0 : 1;
}

inline int uint32_t_cmp(uint32_t *a, uint32_t *b)
{
    return (*a == *b) ? 0 : 1;
}

inline int uint64_t_cmp(uint64_t *a, uint64_t *b)
{
    return (*a == *b) ? 0: 1;
}

inline int ngx_cmp(const ngx_str_t *a, const ngx_str_t *b)
{
    if (a->len == b->len)
        return memcmp(a->data, b->data, a->len);
    else
        return (a->len - b->len);
}

inline int ngx_casecmp(const ngx_str_t *a, const ngx_str_t *b)
{
    if (a->len == b->len)
        return ngx_strncasecmp(a->data, b->data, a->len);
    else
        return (a->len - b->len);
}

inline uint32_t ngx_hash(ngx_str_t *key)
{
    int i;
    uint32_t    sum = 0;
    for (i = 0; i < key->len; i++) {
        if (i % 2)
            sum += key->data[i];
        else
            sum += ((uint16_t)key->data[i]) << 8;
    }
    return sum;
}

char *ngx_print(char *buf, int len, ngx_str_t *p_ngx_str)
{
    if (p_ngx_str->data == NULL
        || p_ngx_str->len <= 0)
    {
        return "null";
    }
        
    len--;
    int cp_len = len > p_ngx_str->len ? p_ngx_str->len : len;
    memcpy(buf, p_ngx_str->data, cp_len);
    buf[cp_len] = 0;
    return buf;
}
/*
orig 可以 等于 part_b
*/
int ngx_split(ngx_str_t *orig, char sepch, ngx_str_t *part_a, ngx_str_t *part_b)
{
    uint8_t *sep = memchr(orig->data, sepch, orig->len);
    if (sep == NULL)
        return -1;

    part_a->data = orig->data;
    part_a->len = sep - orig->data;

    sep++;
    part_b->len = orig->data + orig->len - sep;
    part_b->data = sep;
    return 0;
}


int event_notify(int event_fd)
{
    uint64_t notify = 1;
    if (write(event_fd, &notify, sizeof(notify)) < 0)
        return -1;    
    return 0;
}



/*
 * Removes any new-line or carriage-return characters from the end of the
 * string. This function is named after the same function in Perl.
 * "length" should be the number of characters in the buffer, not including
 * the trailing NULL.
 *
 * Returns the number of characters removed from the end of the string.  A
 * negative return value indicates an error.
 */
ssize_t chomp (char *buffer, size_t length)
{
    size_t chars;

    assert (buffer != NULL);
    assert (length > 0);

    /* Make sure the arguments are valid */
    if (buffer == NULL)
        return -EFAULT;
    if (length < 1)
        return -ERANGE;

    chars = 0;

    --length;
    while (buffer[length] == '\r' || buffer[length] == '\n')
    {
        //buffer[length] = '\0';
        chars++;

        /* Stop once we get to zero to prevent wrap-around */
        if (length-- == 0)
                break;
    }

    return chars;
}

ssize_t chomp_ngx_str (ngx_str_t *ngx_str)
{
    size_t chars;

    assert (ngx_str->data != NULL);
    assert (ngx_str->len > 0);

    /* Make sure the arguments are valid */
    if (ngx_str->data == NULL)
        return -EFAULT;
    if (ngx_str->len < 1)
        return -ERANGE;

    chars = 0;

    int length = ngx_str->len;
    --length;
    while (ngx_str->data[length] == '\r' || ngx_str->data[length] == '\n')
    {
        //ngx_str->data[length] = '\0';
        chars++;

        /* Stop once we get to zero to prevent wrap-around */
        if (length-- == 0)
                break;
    }

    ngx_str->len = ngx_str->len - chars;
    return chars;
}

const char * base64char = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/*
 * 将字符串转换成base64编码
 * 返回转换后的长度
 */
int base64_encode( const unsigned char * bindata, unsigned char *base64, int binlength, int out_len)
{
    int i, j;
    unsigned char current;

    for ( i = 0, j = 0 ; i < binlength && j < out_len ; i += 3 )
    {
        current = (bindata[i] >> 2) ;
        current &= (unsigned char)0x3F;
        base64[j++] = base64char[(int)current];

        current = ( (unsigned char)(bindata[i] << 4 ) ) & ( (unsigned char)0x30 ) ;
        if ( i + 1 >= binlength )
        {
            base64[j++] = base64char[(int)current];
            base64[j++] = '=';
            base64[j++] = '=';
            break;
        }
        current |= ( (unsigned char)(bindata[i+1] >> 4) ) & ( (unsigned char) 0x0F );
        base64[j++] = base64char[(int)current];

        current = ( (unsigned char)(bindata[i+1] << 2) ) & ( (unsigned char)0x3C ) ;
        if ( i + 2 >= binlength )
        {
            base64[j++] = base64char[(int)current];
            base64[j++] = '=';
            break;
        }
        current |= ( (unsigned char)(bindata[i+2] >> 6) ) & ( (unsigned char) 0x03 );
        base64[j++] = base64char[(int)current];

        current = ( (unsigned char)bindata[i+2] ) & ( (unsigned char)0x3F ) ;
        base64[j++] = base64char[(int)current];
    }
    base64[j] = '\0';
    return j;
}

int base64_decode(const char *base64, unsigned char *bindata)
{
    int i, j;
    unsigned char k;
    unsigned char temp[4];
    for ( i = 0, j = 0; base64[i] != '\0' ; i += 4 )
    {
        memset( temp, 0xFF, sizeof(temp) );
        for ( k = 0 ; k < 64 ; k ++ )
        {
            if ( base64char[k] == base64[i] )
                temp[0]= k;
        }
        for ( k = 0 ; k < 64 ; k ++ )
        {
            if ( base64char[k] == base64[i+1] )
                temp[1]= k;
        }
        for ( k = 0 ; k < 64 ; k ++ )
        {
            if ( base64char[k] == base64[i+2] )
                temp[2]= k;
        }
        for ( k = 0 ; k < 64 ; k ++ )
        {
            if ( base64char[k] == base64[i+3] )
                temp[3]= k;
        }

        bindata[j++] = ((unsigned char)(((unsigned char)(temp[0] << 2))&0xFC)) |
                ((unsigned char)((unsigned char)(temp[1]>>4)&0x03));
        if ( base64[i+2] == '=' )
            break;

        bindata[j++] = ((unsigned char)(((unsigned char)(temp[1] << 4))&0xF0)) |
                ((unsigned char)((unsigned char)(temp[2]>>2)&0x0F));
        if ( base64[i+3] == '=' )
            break;

        bindata[j++] = ((unsigned char)(((unsigned char)(temp[2] << 6))&0xF0)) |
                ((unsigned char)(temp[3]&0x3F));
    }
    return j;
}

inline uint32_t  get_network_from_ip(uint32_t ip)
{
    return ip >> 8;
    #if 0
    uint8_t first_byte = (uint8_t)(ip >> 24);
    if (first_byte <= 126)//A
    {
        return ip & 0xff000000;
    }
    else if (first_byte <= 191)//B
    {
        return ip & 0xffff0000;
    }
    else//C
    {
        return ip & 0xffffff00;
    }
    #endif
}

int code_convert( const char* from_charset,
                  const char* to_charset,
                  char* inbuf,
                  size_t inlen,
                  char* outbuf,
                  size_t outlen )
{
    iconv_t cd;
    //int     rc;
    char**  pin   = &inbuf;
    char**  pout  = &outbuf;

    cd = iconv_open( to_charset, from_charset );
    if ( cd == 0 )
    {
        return -1;
    }
    memset( outbuf, 0, outlen );
    if ( iconv( cd, pin, &inlen, pout, &outlen ) == (unsigned int)-1 )
    {
        iconv_close( cd );
        return -1;
    }
    iconv_close( cd );
    return 0;
}

char *date_format(char *buffer, size_t buffer_len, time_t time)
{
    struct tm *timeinfo;

    timeinfo = localtime(&time);
    strftime(buffer, buffer_len, "%Y/%m/%d %H:%M:%S", timeinfo);
    return buffer;
}
