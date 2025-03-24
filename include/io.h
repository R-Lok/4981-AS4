#ifndef IO_H
#define IO_H
#include <unistd.h>

int read_fully(int fd, char *buffer, size_t bytes_to_read);
int write_fully(int fd, const char *data, size_t bytes_to_write);
#endif
