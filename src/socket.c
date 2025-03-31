#include "../include/socket.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define MAX_PENDING_CONNECTIONS 10

int setup_addr(struct sockaddr_in *my_addr, in_port_t port, int *err)
{
    const char *addr = "0.0.0.0";    // Listen to all incoming connections on all availalbe network interfaces

    memset(my_addr, 0, sizeof(struct sockaddr_in));

    my_addr->sin_family = AF_INET;
    my_addr->sin_port   = htons(port);

    if(inet_pton(AF_INET, addr, &(my_addr->sin_addr)) != 1)
    {
        *err = EINVAL;
        return 1;
    }
    return 0;
}

int setup_socket(struct sockaddr_in *my_addr, int *err)
{
    int socket_fd;
    int opt;
    opt = 1;

    socket_fd = socket(my_addr->sin_family, SOCK_STREAM, 0);    // NOLINT(android-cloexec-socket)

    if(socket_fd == -1)
    {
        *err = errno;
        return -1;
    }

    if(setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
    {
        *err = errno;
        goto fail;
    }

    if(bind(socket_fd, (struct sockaddr *)my_addr, sizeof(struct sockaddr_in)) != 0)
    {
        *err = errno;
        goto fail;
    }

    if(listen(socket_fd, MAX_PENDING_CONNECTIONS))
    {
        *err = errno;
        goto fail;
    }

    return socket_fd;
fail:
    close(socket_fd);
    return -1;
}

int set_socket_nonblock(int socket_fd, int *err)
{
    int flags;
    flags = fcntl(socket_fd, F_GETFL, 0);
    if(flags == -1)
    {
        *err = errno;
        return 1;
    }

    if(fcntl(socket_fd, F_SETFL, flags | O_NONBLOCK) == -1)
    {
        *err = errno;
        return 1;
    }
    return 0;
}
