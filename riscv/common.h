// See LICENSE for license details.

#ifndef _RISCV_COMMON_H
#define _RISCV_COMMON_H

#include <cstdio>
#include <pthread.h> 

extern bool running;
extern pthread_mutex_t *json_log_fd_lock;
extern FILE *json_log_fd;

#define   likely(x) __builtin_expect(x, 1)
#define unlikely(x) __builtin_expect(x, 0)

#endif
