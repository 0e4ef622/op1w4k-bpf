#ifndef __OP1W4K_BPF_TYPES
#define __OP1W4K_BPF_TYPES

typedef struct {
    long int timestamp;
    long int delta;
    char button;
} debounce_ev;

#endif // __OP1W4K_BPF_TYPES
