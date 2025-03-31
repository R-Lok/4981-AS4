#include "../include/file_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MIME_TYPE_BUF_SIZE 64

off_t get_resource_size(int fd)
{
    struct stat stats;

    // get stats about the opened file
    if(fstat(fd, &stats))
    {
        return -1;
    }
    // return just the file size
    return stats.st_size;
}

char *get_mime_type(const char *path)
{
    char *type = (char *)malloc(MIME_TYPE_BUF_SIZE);
    if(type == NULL)
    {
        fprintf(stderr, "Malloc error\n");
        return NULL;
    }

    // Chain of strstr calls until pattern matches, if no match, assume text/plain
    if(strstr(path, ".html"))
    {
        strlcpy(type, "text/html", MIME_TYPE_BUF_SIZE);
    }
    else if(strstr(path, ".css"))
    {
        strlcpy(type, "text/css", MIME_TYPE_BUF_SIZE);
    }
    else if(strstr(path, ".js"))
    {
        strlcpy(type, "text/javascript", MIME_TYPE_BUF_SIZE);
    }
    else if(strstr(path, ".jpg") || strstr(path, ".jpeg"))
    {
        strlcpy(type, "image/jpeg", MIME_TYPE_BUF_SIZE);
    }
    else if(strstr(path, ".png"))
    {
        strlcpy(type, "image/png", MIME_TYPE_BUF_SIZE);
    }
    else if(strstr(path, ".gif"))
    {
        strlcpy(type, "image/gif", MIME_TYPE_BUF_SIZE);
    }
    else if(strstr(path, ".swf"))
    {
        strlcpy(type, "application/x-shockwave-flash", MIME_TYPE_BUF_SIZE);
    }
    else
    {
        strlcpy(type, "text/plain", MIME_TYPE_BUF_SIZE);
    }
    return type;
}
