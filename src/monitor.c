#include "../include/monitor.h"
#include "../include/worker.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAX_WORKERS 3

int start_monitor(int child_end, const volatile sig_atomic_t *running)
{
    int num_workers;
    num_workers = 0;

    printf("Monitor started...\n");

    while(*running == 1)
    {
        int fork_res;
        if(num_workers == MAX_WORKERS)
        {
            int status;
            waitpid(-1, &status, 0);    // blocking wait for any child
            num_workers--;
        }
        if(*running == 0)
        {
            break;
        }

        fork_res = fork();
        if(fork_res == -1)
        {
            fprintf(stderr, "fork() failed in start_monitor: Line %d", __LINE__);
            return 1;
        }

        if(fork_res == 0)    // child
        {
            // printf("Worker\n");
            start_worker(child_end, running);
            exit(0);
        }
        else
        {
            num_workers++;
        }
    }
    printf("monitor exiting..\n");
    close(child_end);
    return 0;
}
