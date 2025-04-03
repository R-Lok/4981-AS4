#include "../include/worker.h"
#include "../include/io.h"
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define SHARED_LIB_PATH "./httphandler.so"

int start_worker(int sock_fd, const volatile sig_atomic_t *running, sem_t *sem)
{
    struct stat st;
    time_t      last_mod_time;
    void       *handle;
    int         ret;
    int (*request_handler)(int, sem_t *);

    ret = 0;

    printf("New Worker\n");

    if(stat(SHARED_LIB_PATH, &st))
    {
        perror("stat() error");
        return 1;
    }

    last_mod_time = st.st_mtime;

    handle = dlopen(SHARED_LIB_PATH, RTLD_LAZY);
    if(!handle)
    {
        fprintf(stderr, "dlopen error %s\n", dlerror());
        return 1;
    }

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#pragma GCC diagnostic ignored "-Wstrict-prototypes"
    request_handler = (int (*)(int, sem_t *))dlsym(handle, "handler");
    if(!request_handler)
    {
        fprintf(stderr, "dlsym error %s\n", dlerror());
        dlclose(handle);
        return 1;
    }
#pragma GCC diagnostic pop

    while(*running == 1)
    {
        struct stat st2;
        int         parent_fd_num;    // File descriptor number of the resource in the main server process to send back;
        int         client_fd;

        client_fd = recv_fd(sock_fd, &parent_fd_num, 1);
        if(client_fd == -1)
        {
            ret = 1;
            goto error;
        }

        if(stat(SHARED_LIB_PATH, &st2))
        {
            perror("stat() error");
            return 1;
        }

        if(st2.st_mtime > last_mod_time)
        {    // if newer version of library exists
            if(dlclose(handle))
            {
                fprintf(stderr, "dlclose error %s\n", dlerror());
                return 1;
            }
            handle          = NULL;
            request_handler = NULL;
            handle          = dlopen(SHARED_LIB_PATH, RTLD_LAZY);
            if(!handle)
            {
                fprintf(stderr, "dlopen error %s\n", dlerror());
                return 1;
            }

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#pragma GCC diagnostic ignored "-Wstrict-prototypes"

            request_handler = (int (*)(int, sem_t *))dlsym(handle, "handler");
            if(!request_handler)
            {
                fprintf(stderr, "dlsym error %s\n", dlerror());
                dlclose(handle);
                return 1;
            }
#pragma GCC diagnostic pop
        }

        // printf("Handling...client fd is %d\n", client_fd);
        if(request_handler(client_fd, sem))
        {
            perror("Server error handling client req\n");
            goto error;
        }
        close(client_fd);
        if(send_fd(sock_fd, parent_fd_num, 0))
        {
            perror("Failed to send fd back to main server\n");
            goto error;
        }
    }
error:
    dlclose(handle);
    sem_close(sem);
    printf("Worker exiting...\n");
    return ret;
}
