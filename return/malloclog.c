#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static void *(*real_malloc)(size_t);
static void (*real_free)(void *);
static __thread int busy;

static void init_real(void) {
    if (!real_malloc) {
        real_malloc = dlsym(RTLD_NEXT, "malloc");
        real_free = dlsym(RTLD_NEXT, "free");
    }
}

void *malloc(size_t size) {
    init_real();
    void *p = real_malloc(size);
    if (!busy && size >= 24 && size <= 128) {
        busy = 1;
        dprintf(STDERR_FILENO, "M %p %zu\n", p, size);
        busy = 0;
    }
    return p;
}

void free(void *p) {
    init_real();
    if (!busy && p) {
        busy = 1;
        dprintf(STDERR_FILENO, "F %p\n", p);
        busy = 0;
    }
    real_free(p);
}
