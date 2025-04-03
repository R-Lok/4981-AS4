#include "../include/monitor.h"
#include "../include/server.h"
#include <args.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

#define DEFAULT_PORT 80

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
static volatile sig_atomic_t running = 1;

void handle_signal(int signal);

int main(int argc, char **argv)
{
    struct sigaction sa;
    in_port_t        port;
    pid_t            monitor_id;
    int              socket_pair[2];
    int              ret;

    port = DEFAULT_PORT;

#if defined(__linux__) && defined(__clang__)
    _Pragma("clang diagnostic ignored \"-Wdisabled-macro-expansion\"")
#endif
        sa.sa_handler = handle_signal;    // Works fine on macOS/BSD
    sigemptyset(&sa.sa_mask);             // Block no signals during handler execution
    sa.sa_flags = 0;                      // No SA_RESTART: IO will return EINTR instead of automatically resuming
    if(sigaction(SIGINT, &sa, NULL) == -1)
    {
        perror("sigaction");
        return 1;
    }

    if(parse_port(argc, argv, &port) != 0)    // parse the port from command line args
    {
        exit(EXIT_FAILURE);
    }

    if(socketpair(AF_UNIX, SOCK_STREAM, 0, socket_pair))
    {
        fprintf(stderr, "Error on socketpair()\n");
        exit(EXIT_FAILURE);
    }

    monitor_id = fork();
    if(monitor_id == -1)
    {    // Error
        fprintf(stderr, "Fork() error: Line %d", __LINE__);
        exit(EXIT_FAILURE);
    }

    if(monitor_id == 0)
    {
        // child
        int monitor_ret;
        close(socket_pair[1]);    // close one end

        monitor_ret = start_monitor(socket_pair[0], &running);
        exit(monitor_ret);
    }
    else
    {
        // parent
        close(socket_pair[0]);    // close the other end
        printf("Server running on port: %u\n", port);

        ret = start_server(port, socket_pair[1], &running);
    }
    kill(0, SIGINT);    // SIGINT to all process group members (all children, grandchildren..)
    printf("Server exiting..\n");
    return ret;
}

void handle_signal(int signal)    // Just sets running to 0 when SIGINT is received
{
    if(signal == SIGINT)
    {
        running = 0;
    }
}
