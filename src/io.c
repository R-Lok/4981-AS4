#include "../include/io.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int write_fully(int fd, const char *data, size_t bytes_to_write)
{
    size_t twrote;

    twrote = 0;

    while(twrote != bytes_to_write)    // keep going until entire string has been written to socket
    {
        ssize_t nwrote;
        nwrote = write(fd, data + twrote, bytes_to_write - twrote);
        if(nwrote == -1)
        {
            if(errno == EAGAIN || errno == EINTR)
            {
                continue;
            }
            perror("write error");
            return 1;
        }
        twrote += (size_t)nwrote;
    }
    return 0;
}

int read_fully(int fd, char *buffer, size_t bytes_to_read)
{
    size_t tread;

    tread = 0;
    while(tread != bytes_to_read)
    {
        ssize_t nread;
        nread = read(fd, buffer + tread, bytes_to_read - tread);
        // printf("reading\n");
        if(nread == -1)
        {
            // printf("errno: %d", errno);
            if(errno == EINTR || errno == EAGAIN)
            {
                continue;
            }
            if(errno == ECONNRESET)
            {
                return 1;
            }
            fprintf(stderr, "read() error at line %d\n", __LINE__);
            return -1;
        }
        if(nread == 0)
        {
            return 1;    // EOF, closed connection
        }
        tread += (size_t)nread;
    }
    return 0;
}
