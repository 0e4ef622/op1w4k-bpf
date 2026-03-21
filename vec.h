#include <stdlib.h>
#include <string.h>

#define vec_define(T)                                                          \
    typedef struct {                                                           \
        T *data;                                                               \
        int length;                                                            \
        int capacity;                                                          \
    } vec_##T

vec_define(void);
static void _vec_grow(vec_void *vec, int elem_size) {
    if (vec->capacity == 0) {
        vec->data = malloc(4 * elem_size);
        vec->capacity = 4;
    }
    if (vec->length == vec->capacity) {
        vec->data = realloc(vec->data, vec->capacity * 2 * elem_size);
        vec->capacity *= 2;
    }
}

#define vec_new() {0}

#define _vec_elem_size(vec_ptr) (sizeof(*(vec_ptr)->data))

#define vec_push(vec_ptr, item)                                                \
    do {                                                                       \
        _vec_grow((vec_void *)vec_ptr, _vec_elem_size(vec_ptr));               \
        (vec_ptr)->data[(vec_ptr)->length] = (item);                           \
        (vec_ptr)->length += 1;                                                \
    } while (0)

#define vec_pop(vec_ptr) (vec_ptr)->length -= 1

#define vec_remove(vec_ptr, i)                                                 \
    do {                                                                       \
        int n = ((vec_ptr)->length - (i) - 1) * _vec_elem_size(vec_ptr);       \
        memmove((vec_ptr)->data + i, (vec_ptr)->data + i + 1, n);              \
        (vec_ptr)->length -= 1;                                                \
    } while (0)

#define vec_free(vec_ptr) free((vec_ptr)->data)
