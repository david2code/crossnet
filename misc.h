#ifndef __FUNCTION_H__
#define __FUNCTION_H__

#include <stdbool.h>
#include <ctype.h>

typedef struct {
    size_t      len;
    uint8_t     *data;
} ngx_str_t;

typedef struct{
    uint8_t       type;
    uint16_t      length;
    uint8_t       value[0];
}__attribute__((packed)) tlv_node_t;



#define LF          (uint8_t) '\n'
#define CR          (uint8_t) '\r'
#define CRLF        "\r\n"
#define CRLFCRLF    "\r\n\r\n"

#define NGX_HTTP_UNKNOWN                   0x0001
#define NGX_HTTP_GET                       0x0002
#define NGX_HTTP_HEAD                      0x0004
#define NGX_HTTP_POST                      0x0008
#define NGX_HTTP_PUT                       0x0010
#define NGX_HTTP_DELETE                    0x0020
#define NGX_HTTP_MKCOL                     0x0040
#define NGX_HTTP_COPY                      0x0080
#define NGX_HTTP_MOVE                      0x0100
#define NGX_HTTP_OPTIONS                   0x0200
#define NGX_HTTP_PROPFIND                  0x0400
#define NGX_HTTP_PROPPATCH                 0x0800
#define NGX_HTTP_LOCK                      0x1000
#define NGX_HTTP_UNLOCK                    0x2000
#define NGX_HTTP_PATCH                     0x4000
#define NGX_HTTP_TRACE                     0x8000

#define NGX_HTTP_CLIENT_ERROR              10
#define NGX_HTTP_PARSE_INVALID_METHOD      10
#define NGX_HTTP_PARSE_INVALID_REQUEST     11
#define NGX_HTTP_PARSE_INVALID_09_METHOD   12

#define NGX_HTTP_PARSE_INVALID_HEADER      13


#ifndef NGX_HAVE_NONALIGNED
#define NGX_HAVE_NONALIGNED  1
#endif

#ifndef NGX_HAVE_LITTLE_ENDIAN
#define NGX_HAVE_LITTLE_ENDIAN  1
#endif

#if (NGX_HAVE_LITTLE_ENDIAN && NGX_HAVE_NONALIGNED)

#define ngx_str3_cmp(m, c0, c1, c2, c3)                                       \
    *(uint32_t *) m == ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0)

#define ngx_str3Ocmp(m, c0, c1, c2, c3)                                       \
    *(uint32_t *) m == ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0)

#define ngx_str4cmp(m, c0, c1, c2, c3)                                        \
    *(uint32_t *) m == ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0)

#define ngx_str5cmp(m, c0, c1, c2, c3, c4)                                    \
    *(uint32_t *) m == ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0)             \
        && m[4] == c4

#define ngx_str6cmp(m, c0, c1, c2, c3, c4, c5)                                \
    *(uint32_t *) m == ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0)             \
        && (((uint32_t *) m)[1] & 0xffff) == ((c5 << 8) | c4)

#define ngx_str7_cmp(m, c0, c1, c2, c3, c4, c5, c6, c7)                       \
    *(uint32_t *) m == ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0)             \
        && ((uint32_t *) m)[1] == ((c7 << 24) | (c6 << 16) | (c5 << 8) | c4)

#define ngx_str8cmp(m, c0, c1, c2, c3, c4, c5, c6, c7)                        \
    *(uint32_t *) m == ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0)             \
        && ((uint32_t *) m)[1] == ((c7 << 24) | (c6 << 16) | (c5 << 8) | c4)

#define ngx_str9cmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8)                    \
    *(uint32_t *) m == ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0)             \
        && ((uint32_t *) m)[1] == ((c7 << 24) | (c6 << 16) | (c5 << 8) | c4)  \
        && m[8] == c8

#else /* !(NGX_HAVE_LITTLE_ENDIAN && NGX_HAVE_NONALIGNED) */

#define ngx_str3_cmp(m, c0, c1, c2, c3)                                       \
    m[0] == c0 && m[1] == c1 && m[2] == c2

#define ngx_str3Ocmp(m, c0, c1, c2, c3)                                       \
    m[0] == c0 && m[2] == c2 && m[3] == c3

#define ngx_str4cmp(m, c0, c1, c2, c3)                                        \
    m[0] == c0 && m[1] == c1 && m[2] == c2 && m[3] == c3

#define ngx_str5cmp(m, c0, c1, c2, c3, c4)                                    \
    m[0] == c0 && m[1] == c1 && m[2] == c2 && m[3] == c3 && m[4] == c4

#define ngx_str6cmp(m, c0, c1, c2, c3, c4, c5)                                \
    m[0] == c0 && m[1] == c1 && m[2] == c2 && m[3] == c3                      \
        && m[4] == c4 && m[5] == c5

#define ngx_str7_cmp(m, c0, c1, c2, c3, c4, c5, c6, c7)                       \
    m[0] == c0 && m[1] == c1 && m[2] == c2 && m[3] == c3                      \
        && m[4] == c4 && m[5] == c5 && m[6] == c6

#define ngx_str8cmp(m, c0, c1, c2, c3, c4, c5, c6, c7)                        \
    m[0] == c0 && m[1] == c1 && m[2] == c2 && m[3] == c3                      \
        && m[4] == c4 && m[5] == c5 && m[6] == c6 && m[7] == c7

#define ngx_str9cmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8)                    \
    m[0] == c0 && m[1] == c1 && m[2] == c2 && m[3] == c3                      \
        && m[4] == c4 && m[5] == c5 && m[6] == c6 && m[7] == c7 && m[8] == c8

#endif



typedef struct {
    ngx_str_t   key;
    ngx_str_t   value;
} ngx_keyval_t;


#define ngx_string(str)     { sizeof(str) - 1, (uint8_t *) str }
#define ngx_null_string     { 0, NULL }
#define ngx_str_set(str, text)                                               \
    (str)->len = sizeof(text) - 1; (str)->data = (uint8_t *) text
#define ngx_str_null(str)   (str)->len = 0; (str)->data = NULL


#define ngx_tolower(c)      (uint8_t) ((c >= 'A' && c <= 'Z') ? (c | 0x20) : c)
#define ngx_toupper(c)      (uint8_t) ((c >= 'a' && c <= 'z') ? (c & ~0x20) : c)


typedef intptr_t        ngx_int_t;
typedef uintptr_t       ngx_uint_t;
typedef intptr_t        ngx_flag_t;

#define ngx_strncmp(s1, s2, n)  strncmp((const char *) s1, (const char *) s2, n)

#define ngx_strlen(s)       strlen((const char *) s)

uint32_t get_ip_by_hostname(const char *hostname);
uint32_t jhash(const void *key, uint32_t length, uint32_t initval);
int create_listen_socket(uint16_t port, int back_log);
int create_listen_socket_at_address(uint32_t ip, uint16_t port, int back_log);
int create_listen_socket_nodelay(uint16_t port, int back_log);
int create_socket_to_server(uint32_t ip, uint16_t port, int connect_timeout);
int create_socket_to_server2(char *ip_str, uint16_t port, int connect_timeout);
int set_none_block(int fd);
void add_event(int epollfd, int fd, void *ptr, int state);
void delete_event(int epollfd, int fd, void *ptr, int state);
void modify_event(int epollfd,int fd, void *ptr, int state);
char *u64_to_mac_str(char *mac, int len, uint64_t mac_u64);
uint64_t mac_str_to_u64(char *mac);
uint64_t str_to_u64_base10(char *str);
uint32_t str_to_u32_base10(char *str);
uint16_t str_to_u16_base10(char *str);
bool is_new_day(time_t last_time, time_t now_time);
tlv_node_t *tlv_node_fill(tlv_node_t *p_tlv, uint8_t type, char *value);
tlv_node_t *tlv_node_fill_uint8_t(tlv_node_t *p_tlv, uint8_t type, uint8_t value);
tlv_node_t *tlv_node_fill_uint16_t(tlv_node_t *p_tlv, uint8_t type, uint16_t value);
tlv_node_t *tlv_node_fill_uint32_t(tlv_node_t *p_tlv, uint8_t type, uint32_t value);
tlv_node_t *tlv_node_fill_uint64_t(tlv_node_t *p_tlv, uint8_t type, uint64_t value);
tlv_node_t *tlv_node_fill_with_length(tlv_node_t *p_tlv, uint8_t type, uint8_t *value, uint16_t length);
ngx_int_t ngx_strncasecmp(uint8_t *s1, uint8_t *s2, size_t n);
uint8_t *ngx_strnstr(uint8_t *s1, char *s2, size_t len);
ngx_int_t ngx_strcasecmp(uint8_t *s1, uint8_t *s2);

int url_str_decode(char *dest, const char *src, int dest_len);
int url_str_decode2(ngx_str_t *p_ngx_dest, ngx_str_t *p_ngx_src);

char* calculate_host_url_keyword(const char *host, const char *url, char *key_word);
void string_process_for_mysql( char* dstStr, const char* srcStr, int dstLen);
uint8_t *
ngx_strnstrn(uint8_t *s1, uint8_t *s2, size_t len, size_t s2_len);

void trim_space(ngx_str_t *str);

int get_middle_str(const ngx_str_t *str, const ngx_str_t *left, const ngx_str_t *right, ngx_str_t *mid);

int uri_parse(ngx_str_t *uri, ngx_str_t *host, ngx_str_t *url);
uint16_t get_port_from_host(const char *host);
int check_is_process_alive(const char *proc_name);
uint64_t get_eth_mac(const char *eth_name);
uint32_t get_eth_ip(const char *eth_name);
uint32_t get_addrinfo(char *host);
unsigned long long ntohll(unsigned long long val);
unsigned long long htonll(unsigned long long val);
inline int uint16_t_cmp(uint16_t *a, uint16_t *b);
inline int uint32_t_cmp(uint32_t *a, uint32_t *b);
inline int uint64_t_cmp(uint64_t *a, uint64_t *b);
inline int ngx_cmp(ngx_str_t *a, ngx_str_t *b);
inline uint32_t ngx_hash(ngx_str_t *key);

uint16_t lt_make_send_cmd(uint8_t *p_buf, uint16_t type, int seq_id);
char *ngx_print(char *buf, int len, ngx_str_t *p_ngx_str);
int ngx_split(ngx_str_t *orig, char sepch, ngx_str_t *part_a, ngx_str_t *part_b);
int event_notify(int event_fd);
bool is_new_hour(time_t last_time, time_t now_time);
int get_hour(time_t now_time);
ssize_t chomp (char *buffer, size_t length);
ssize_t chomp_ngx_str (ngx_str_t *ngx_str);
int base64_encode( const unsigned char * bindata, unsigned char *base64, int binlength, int out_len);
int base64_decode(const char *base64, unsigned char *bindata);
inline uint32_t  get_network_from_ip(uint32_t ip);
int create_udp_listen_socket(uint16_t *port);
int code_convert( const char* from_charset,
                  const char* to_charset,
                  char* inbuf,
                  size_t inlen,
                  char* outbuf,
                  size_t outlen );


#endif
