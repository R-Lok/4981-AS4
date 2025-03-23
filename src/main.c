#include <args.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

#define DEFAULT_PORT 8000

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
static volatile sig_atomic_t running = 1;

void handle_signal(int signal);

int main(int argc, char **argv)
{
    struct sigaction sa;
    in_port_t        port;

    port = DEFAULT_PORT;

    sa.sa_handler = handle_signal;    // Works fine on macOS/BSD
    sigemptyset(&sa.sa_mask);         // Block no signals during handler execution
    sa.sa_flags = 0;                  // No SA_RESTART: IO will return EINTR instead of automatically resuming
    if(sigaction(SIGINT, &sa, NULL) == -1)
    {
        perror("sigaction");
        return 1;
    }

    if(parse_port(argc, argv, &port) != 0)    // parse the port from command line args
    {
        exit(EXIT_FAILURE);
    }

    printf("port: %u\n", port);
}

void handle_signal(int signal)    // Just sets running to 0 when SIGINT is received
{
    if(signal == SIGINT)
    {
        running = 0;
    }
}
