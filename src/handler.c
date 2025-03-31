#include "../include/handler.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int handle_request(int client_fd)
{
    const char *test = "test";
    printf("Hello | %d\n", client_fd);
    write(client_fd, test, strlen(test));
    return 0;
}
