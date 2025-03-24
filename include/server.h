#ifndef SERVER_H
#define SERVER_H
#include <netinet/in.h>
#include <signal.h>

int start_server(in_port_t port, int workers_fd, const volatile sig_atomic_t *running);

#endif
