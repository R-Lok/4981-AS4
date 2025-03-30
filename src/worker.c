#include "../include/worker.h"
#include <dlfcn.h>
#include <stdio.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define SHARED_LIB_PATH "./httphandler.so"

int start_worker(int sock_fd, const volatile sig_atomic_t *running)
{
    struct stat st;
    time_t      last_mod_time;
    void       *handle;
    int (*request_handler)(int);

    printf("Hello from worker\n | %d %d\n", sock_fd, *running);

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
    request_handler = (int (*)(int))dlsym(handle, "handle_request");
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

            request_handler = (int (*)())dlsym(handle, "handle_request");
            if(!request_handler)
            {
                fprintf(stderr, "dlsym error %s\n", dlerror());
                dlclose(handle);
                return 1;
            }
#pragma GCC diagnostic pop
        }

        request_handler(1);
        sleep(3);
    }
    return 0;
}
