#include "../include/monitor.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAX_WORKERS 3

int start_monitor(int child_end, const volatile sig_atomic_t *running)
{
    int num_workers;
    num_workers = 0;

    printf("child end: %d", child_end);

    while(*running == 1)
    {
        int fork_res;
        printf("monitor running..\n");
        if(num_workers == MAX_WORKERS)
        {
            int status;
            waitpid(-1, &status, 0);    // blocking wait for any child
            num_workers--;
        }

        fork_res = fork();
        if(fork_res == -1)
        {
            fprintf(stderr, "fork() failed in start_monitor: Line %d", __LINE__);
            return 1;
        }

        if(fork_res == 0)    // child
        {
            // int worker_res;
            printf("Worker\n");
            while(*running)
            {
            }
            exit(0);
        }
    }
    printf("monitor exiting..\n");
    close(child_end);
    return 0;
}
