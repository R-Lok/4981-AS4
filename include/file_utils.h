#ifndef FILE_UTILS_H
#define FILE_UTILS_H
#include <sys/stat.h>

off_t get_resource_size(int fd);
char *get_mime_type(const char *path);

#endif
