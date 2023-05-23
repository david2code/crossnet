#ifndef _HASH_TABLE_H
#define _HASH_TABLE_H
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#include "misc.h"

/* 2.6.32-279.el6.x86_64/include/linux/kernel.h  */  
#define container_of(ptr, type, member) ({                      \
        const typeof( ((type *)0)->member ) *__mptr = (ptr);   \
        (type *)( (char *)__mptr - offsetof(type,member) );})  


struct hash_table {
    struct list_head    *p_hash_head;

    char                table_name[TABLE_NAME_LEN + 1];
    uint32_t            size;

    uint32_t            node_size;
    uint32_t            count;
    pthread_mutex_t     mutex;
};

/*动态hash函数*/
#define DHASH_GENERATE(name, type, hash_node_field, hash_key_field, hash_key_type, hash_func, hash_cmp)				\
/* init hash table */               \
int                                         \
name##_HASH_INIT(struct hash_table *p_table, uint32_t hash_size)                          \
{                                           \
    strncpy(p_table->table_name, #name, TABLE_NAME_LEN); \
    p_table->table_name[TABLE_NAME_LEN] = 0; \
    p_table->size = hash_size;                       \
    p_table->node_size = sizeof(struct type);   \
    p_table->count = 0;                         \
    pthread_mutex_init(&p_table->mutex, NULL);  \
    p_table->p_hash_head = (struct list_head *)malloc(sizeof(struct list_head) * p_table->size);\
    if (NULL == p_table->p_hash_head)   \
        return -1;                  \
    int i;                          \
    for (i = 0; i < p_table->size; i++) {       \
        struct list_head *p_head = &(p_table->p_hash_head[i]);\
        p_head->next = p_head;      \
        p_head->prev = p_head;      \
    }                               \
    return 0;                       \
}                                   \
/* Finds the node with the same key as elm */               \
struct type *                               \
name##_HASH_FIND(struct hash_table *p_table, hash_key_type *elm)         \
{                                   \
    uint32_t    hash_value = hash_func(elm) % p_table->size;    \
    struct list_head *p_head = &p_table->p_hash_head[hash_value];               \
    struct list_head *p_pos;   \
    list_for_each(p_pos, p_head){                           \
        struct type *p_entry = container_of(p_pos, struct type, hash_node_field);\
        if (0 == hash_cmp(elm, &p_entry->hash_key_field)){                   \
            return (p_entry);                   \
        }                               \
    }                               \
    return (NULL);                          \
}                                   \
/* insert the node to hash table */               \
int                            \
name##_HASH_INSERT(struct hash_table *p_table, struct type *p_node)         \
{                                   \
    uint32_t    hash_value = hash_func(&p_node->hash_key_field) % p_table->size;    \
    struct list_head *p_head = &p_table->p_hash_head[hash_value];               \
    struct list_head *p_pos;   \
    list_for_each(p_pos, p_head){                           \
        struct type *p_entry = container_of(p_pos,struct type,hash_node_field);\
        if (0 == hash_cmp(&p_node->hash_key_field, &p_entry->hash_key_field)){                   \
            return -1;                   \
        }                               \
    }                               \
    list_add_fe(&p_node->hash_node_field, p_head);\
    return 0;                          \
}                                   \
/* insert the node to hash table ignore same*/               \
int                            \
name##_HASH_INSERT_IGNORE_SAME(struct hash_table *p_table, struct type *p_node)         \
{                                   \
    uint32_t    hash_value = hash_func(&p_node->hash_key_field) % p_table->size;    \
    struct list_head *p_head = &p_table->p_hash_head[hash_value];               \
    list_add_fe(&p_node->hash_node_field, p_head);\
    return 0;                           \
}

#define DHASH_INIT(name, p_table, hash_size)	        name##_HASH_INIT(p_table, hash_size)
#define DHASH_FIND(name, p_table, elm)	                name##_HASH_FIND(p_table, elm)
#define DHASH_INSERT(name, p_table, p_node)	            name##_HASH_INSERT(p_table, p_node)
#define DHASH_INSERT_IGNORE_SAME(name, p_table, p_node)	name##_HASH_INSERT_IGNORE_SAME(p_table, p_node)

#endif	/* _HASHTABLE_H */
