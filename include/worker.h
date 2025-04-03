#ifndef WORKER_H
#define WORKER_H
#include <semaphore.h>
#include <signal.h>

int start_worker(int sock_fd, const volatile sig_atomic_t *running, sem_t *sem);

#endif
