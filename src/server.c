#include "../include/server.h"
#include "../include/io.h"
#include "../include/socket.h"
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_CONNECTIONS 1024
#define SOCK_FD_INDEX 0
#define WORKER_FD_INDEX 1

int  server_loop(int sock_fd, int workers_fd, struct sockaddr_in *addr, const volatile sig_atomic_t *running);
int  handle_poll_events(struct pollfd *pollfds, nfds_t *num_poll_fds, int workers_fd, int sock_fd, struct sockaddr_in *addr);
void add_pollfd(struct pollfd *pollfds, nfds_t *num_fds, int new_fd);
void remove_pollfd(struct pollfd *pollfds, nfds_t *num_fds, nfds_t index);
int  handle_worker_msg(int fd);
int  send_fd(int workers_fd, int req_fd);

int start_server(in_port_t port, int workers_fd, const volatile sig_atomic_t *running)
{
    struct sockaddr_in addr;
    int                err;
    int                sock_fd;
    int                server_loop_res;

    if(setup_addr(&addr, port, &err))    // set up address structs for socket setup
    {
        fprintf(stderr, "Error setting up sockaddr_in %s", strerror(err));
        return 1;
    }

    sock_fd = setup_socket(&addr, &err);
    if(sock_fd == -1)
    {
        fprintf(stderr, "Error setting up socket %s", strerror(err));
        return 1;
    }

    server_loop_res = server_loop(sock_fd, workers_fd, &addr, running);
    return server_loop_res;
}

int server_loop(int sock_fd, int workers_fd, struct sockaddr_in *addr, const volatile sig_atomic_t *running)
{
    struct pollfd *pollfds;
    nfds_t         num_fds;
    int            ret = 0;

    pollfds = (struct pollfd *)malloc(sizeof(struct pollfd) * MAX_CONNECTIONS);
    if(pollfds == NULL)
    {
        fprintf(stderr, "malloc() error in server_loop: Line %d", __LINE__);
        return 1;
    }

    pollfds[SOCK_FD_INDEX].fd       = sock_fd;
    pollfds[SOCK_FD_INDEX].events   = POLLIN;
    pollfds[WORKER_FD_INDEX].fd     = workers_fd;
    pollfds[WORKER_FD_INDEX].events = POLLIN;
    num_fds                         = 2;

    while(*running == 1)
    {
        if(poll(pollfds, num_fds, -1))
        {
            if(errno == EINTR)
            {
                continue;
            }
            fprintf(stderr, "poll() error: %s\n", strerror(errno));
            ret = 1;
            break;
        }

        if(handle_poll_events(pollfds, &num_fds, workers_fd, sock_fd, addr))
        {
            fprintf(stderr, "handle_poll_events error\n");
            ret = 1;
            break;
        }
    }
    free(pollfds);
    return ret;
}

int handle_poll_events(struct pollfd *pollfds, nfds_t *num_poll_fds, int workers_fd, int sock_fd, struct sockaddr_in *addr)
{
    for(nfds_t i = 0; i < *num_poll_fds; i++)
    {
        if(pollfds[i].revents & POLLIN)
        {
            if(pollfds[i].fd == sock_fd)
            {
                int       new_fd;
                socklen_t sock_len;
                sock_len = (socklen_t)sizeof(*addr);

                new_fd = accept(sock_fd, (struct sockaddr *)addr, &sock_len);
                if(new_fd == -1)
                {
                    if(errno == EINTR)
                    {
                        continue;
                    }
                    fprintf(stderr, "accept() error\n");
                    return 1;    // error
                }
                add_pollfd(pollfds, num_poll_fds, new_fd);
            }
            else if(pollfds[i].fd == workers_fd)
            {
                if(handle_worker_msg(pollfds[i].fd))
                {
                    return 1;    // error
                }
                continue;
            }
            else
            {
                pollfds[i].events = POLLNVAL;    // stop reading POLLIN events for now, have to handle existing request
                if(send_fd(workers_fd, pollfds[i].fd))
                {
                    return 1;    // error sending fd to workers
                }
            }
        }
        if(pollfds[i].revents & POLL_HUP)
        {
            close(pollfds[i].fd);
            continue;
        }
        if(pollfds[i].revents & POLLNVAL)
        {
            remove_pollfd(pollfds, num_poll_fds, i);
            i--;    // Decrement to repeat this iteration as we just replaced the pollfd at this index
        }
    }
    return 0;
}

void add_pollfd(struct pollfd *pollfds, nfds_t *num_fds, int new_fd)
{
    nfds_t nfd;

    nfd = *num_fds;

    pollfds[nfd].fd     = new_fd;
    pollfds[nfd].events = POLLIN | POLL_HUP | POLLNVAL;

    (*num_fds)++;
}

void remove_pollfd(struct pollfd *pollfds, nfds_t *num_fds, nfds_t index)
{
    nfds_t nfd;

    nfd = (*num_fds) - 1;    // last filled index is num_fds - 1

    pollfds[index].fd      = pollfds[nfd].fd;
    pollfds[index].events  = pollfds[nfd].events;
    pollfds[index].revents = pollfds[nfd].revents;

    pollfds[nfd].fd      = -1;    // set to invalid fd
    pollfds[nfd].events  = 0;     // zero out flags
    pollfds[nfd].revents = 0;     // zero out flags

    (*num_fds)--;    // decrement number of fds
}

int handle_worker_msg(int fd)
{
    int fd_num;
    int read_res;

    read_res = read_fully(fd, (char *)&fd_num, sizeof(fd_num));
    if(read_res == -1)
    {
        return 1;
    }

    if(close(fd_num))
    {
        perror("failed to close fd");
        return 1;    // failed to close fd;
    }
    return 0;
}

int send_fd(int workers_fd, int req_fd)
{
    struct msghdr   msg = {0};
    struct iovec    io;
    struct cmsghdr *cmsg;
    int             fd_number;

    char control[CMSG_SPACE(sizeof(int))];
    fd_number = req_fd;

    io.iov_base = &fd_number;    // store fd number in parent as part of data to send to client
    io.iov_len  = sizeof(fd_number);

    msg.msg_iov    = &io;
    msg.msg_iovlen = 1;

    msg.msg_control    = control;
    msg.msg_controllen = sizeof(control);

    cmsg             = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type  = SCM_RIGHTS;
    cmsg->cmsg_len   = CMSG_LEN(sizeof(int));

    memcpy(CMSG_DATA(cmsg), &req_fd, sizeof(int));

    if(sendmsg(workers_fd, &msg, 0) < 0)
    {
        perror("error passing file descriptor");
        return 1;
    }
    return 0;
}
