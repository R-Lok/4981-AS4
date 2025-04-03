#include "../include/monitor.h"
#include "../include/worker.h"
#include <fcntl.h>
#include <semaphore.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAX_WORKERS 3
#define SEM_NAME "/as4_sem"
#define SEM_PERMS 0664

int start_monitor(int child_end, const volatile sig_atomic_t *running)
{
    int    num_workers;
    sem_t *sem;
    num_workers = 0;

    printf("Monitor started...\n");

    sem = sem_open(SEM_NAME, O_CREAT, SEM_PERMS, 1);
    if(sem == SEM_FAILED)
    {
        perror("sem_open failed");
        return 1;
    }

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
            start_worker(child_end, running, sem);
            exit(0);
        }
        else
        {
            num_workers++;
        }
    }
    printf("monitor exiting..\n");
    sem_unlink(SEM_NAME);
    close(child_end);
    return 0;
}
