#include "../include/io.h"
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#define READ_BUF_SIZE 1024

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

int send_fd(int workers_fd, int req_fd, int is_pass_fd)
{
    struct msghdr msg = {0};
    struct iovec  io;
    int           fd_number;

    char control[CMSG_SPACE(sizeof(int))];
    fd_number = req_fd;

    io.iov_base = &fd_number;    // store fd number in parent as part of data to send to client
    io.iov_len  = sizeof(fd_number);

    msg.msg_iov    = &io;
    msg.msg_iovlen = 1;

    if(is_pass_fd)
    {
        struct cmsghdr *cmsg;
        msg.msg_control    = control;
        msg.msg_controllen = sizeof(control);

        cmsg             = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type  = SCM_RIGHTS;
        cmsg->cmsg_len   = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(cmsg), &req_fd, sizeof(int));
    }

    if(sendmsg(workers_fd, &msg, 0) < 0)
    {
        perror("error passing file descriptor");
        return 1;
    }
    printf("sent fd\n");
    return 0;
}

int recv_fd(int sock_fd, int *parent_fd_number, int is_expect_passed_fd)
{
    int           passed_fd;
    struct msghdr msg = {0};
    struct iovec  io;
    char          control[CMSG_SPACE(sizeof(int))];

    io.iov_base    = parent_fd_number;
    io.iov_len     = sizeof(*parent_fd_number);
    msg.msg_iov    = &io;
    msg.msg_iovlen = 1;

    msg.msg_control    = control;
    msg.msg_controllen = sizeof(control);

    if(recvmsg(sock_fd, &msg, 0) < 0)
    {
        perror("recvmsg");
        return -1;
    }

    if(is_expect_passed_fd)
    {
        struct cmsghdr *cmsg;
        cmsg = CMSG_FIRSTHDR(&msg);
        if(cmsg && cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS)
        {
            memcpy(&passed_fd, CMSG_DATA(cmsg), sizeof(int));
            return passed_fd;
        }
    }
    return -1;
}

int copy(int sock_fd, int resource_fd)
{
    ssize_t nread;
    char    buf[READ_BUF_SIZE];

    // While reading from the requested resource is not EOF
    while((nread = read(resource_fd, buf, READ_BUF_SIZE)) != 0)
    {
        size_t twrote;
        twrote = 0;

        if(nread == -1)
        {
            if(errno == EINTR)
            {
                continue;    // continue if it was an interrupt
            }
            perror("read error -");
            return 1;
        }
        while(twrote < (size_t)nread)
        {    // while the amount written is less than the amount read
            ssize_t nwrote;

            nwrote = write(sock_fd, buf, (size_t)nread);    // write to socket
            if(nwrote == -1)
            {
                printf("err: %d\n", errno);
                if(errno == EINTR || errno == EWOULDBLOCK || errno == EAGAIN)
                {    // if error due to interrupt, continue
                    struct pollfd pfd;
                    pfd.fd     = sock_fd;
                    pfd.events = POLLOUT;
                    if(poll(&pfd, 1, -1) == -1)
                    {
                        perror("poll");
                        return -1;
                    }
                    errno = 0;
                    continue;
                }
                perror("write error-");
                return 1;
            }
            twrote += (size_t)nwrote;
        }
    }
    return 0;
}
