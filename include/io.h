#ifndef IO_H
#define IO_H
#include <unistd.h>

int read_fully(int fd, char *buffer, size_t bytes_to_read);
int write_fully(int fd, const char *data, size_t bytes_to_write);
int send_fd(int workers_fd, int req_fd, int is_pass_fd);
int recv_fd(int sock_fd, int *parent_fd_number, int is_expect_passed_fd);
int copy(int sock_fd, int resource_fd);
#endif
