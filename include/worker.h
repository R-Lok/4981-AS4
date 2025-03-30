#ifndef WORKER_H
#define WORKER_H
#include <signal.h>

int start_worker(int sock_fd, const volatile sig_atomic_t *running);

#endif
