#ifndef HANDLER_H
#define HANDLER_H
/*
This is the header file for shared library, it's just included here so you can see the code for the shared library.
*/

#define CHUNK_SIZE 1024
#define TIME_OUT_SECONDS 3

#define BAD_REQUEST 400
#define FORBIDDEN 403
#define NOT_FOUND 404
#define METHOD_NOT_ALLOWED 405
#define NOT_IMPLEMENTED 501
#define HTTP_VERSION_NOT_SUPPORTED 505
#define REQUEST_TIMEOUT 408
#define INTERNAL_SERVER_ERROR 500

#define METHOD_HEAD 0
#define METHOD_GET 1
#define METHOD_POST 2

#define MAX_PATH_LENGTH 4096
#define MAX_FULL_PATH_LENGTH 4200
#define MAX_METHOD_LENGTH 16
#define MAX_HTTP_VERSION_LENGTH 8
#define OK_RES_HEADER_BUF_SIZE 1024
#define ERR_RES_BUF_SIZE 2048
#define RES_STATUS_BUF_SIZE 128

#define ROOT "./public"
#define POST_MAX_PAYLOAD 1024

struct request_params
{
    // cppcheck-suppress unusedStructMember
    char method[MAX_METHOD_LENGTH + 1];
    // cppcheck-suppress unusedStructMember
    char path[MAX_FULL_PATH_LENGTH + 1];
    // cppcheck-suppress unusedStructMember
    int method_code;
};

int handler(int client_fd);

#endif
