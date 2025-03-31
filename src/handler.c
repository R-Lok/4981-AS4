#include "../include/handler.h"
#include "../include/file_utils.h"
#include "../include/io.h"
#include "../include/socket.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static void *handle_connection(int fd);
static char *read_request(int fd, int *error);
static int   check_complete(char *buffer, size_t buffer_len);
static void  send_error(int fd, int code);
static int   validate_request(char *request, struct request_params *params);
static int   validate_http_method(const char *method);
static int   validate_http_version(const char *version);
static char *get_time(void);
static void  handle_request(int fd, char *path, int is_get);
static int   open_resource(char *path, int *err);
static int   send_200_res(const int *sock_fd, const int *file_fd, const char *mime_type, off_t resource_len);
static void  url_decode(char *input);
static void  trim_queries(const char *path);

int handler(int client_fd)
{
    printf("Hello | %d\n", client_fd);
    handle_connection(client_fd);
    close(client_fd);
    return 0;
}

static void *handle_connection(int fd)
{
    char                 *request;
    int                   err;
    int                   validate_res;
    struct request_params params;

    printf("new connection, fd = %d\n", fd);

    // set socket connection to nonblocking so we can implement a time-out mechanism
    if(set_socket_nonblock(fd, &err))
    {
        fprintf(stdout, "Error setting socket to non-blocking - %s\n", strerror(err));
        send_error(fd, INTERNAL_SERVER_ERROR);
        goto end;
    }

    // read the request from the socket
    request = read_request(fd, &err);
    if(request == NULL)
    {
        if(err == 1)
        {
            // send error 500
            send_error(fd, INTERNAL_SERVER_ERROR);
        }
        else if(err == 2)
        {
            // send error 408
            send_error(fd, REQUEST_TIMEOUT);
        }
        goto end;
    }
    printf("%s\n", request);

    validate_res = validate_request(request, &params);
    if(validate_res)
    {
        send_error(fd, validate_res);
        goto fail_validate;
    }

    url_decode(params.path);      // Decodes the path if it is encoded
    trim_queries(params.path);    // trims any query arguments from the path as server does not need them

    // Run same method with different flag depending on GET or HEAD request
    if(strcmp(params.method, "GET") == 0)
    {
        handle_request(fd, params.path, METHOD_GET);
    }
    else
    {
        handle_request(fd, params.path, METHOD_HEAD);
    }

fail_validate:
    free(request);
end:
    return NULL;
}

static char *read_request(int fd, int *error)
{
    time_t start_time;
    size_t tread;
    size_t buffer_size;
    char  *buffer;

    start_time  = time(NULL);
    tread       = 0;
    buffer_size = CHUNK_SIZE + 1;

    buffer = (char *)malloc(CHUNK_SIZE + 1);
    if(buffer == NULL)
    {
        fprintf(stderr, "malloc failed\n");
        *error = 1;
        return NULL;
    }

    do
    {
        ssize_t nread;
        time_t  time_now;
        time_now = time(NULL);

        if(difftime(time_now, start_time) >= TIME_OUT_SECONDS)
        {
            *error = 2;
            free(buffer);
            return NULL;
        }

        if((buffer_size - tread) <= CHUNK_SIZE)
        {
            char *temp_buffer;
            buffer_size *= 2;
            temp_buffer = (char *)realloc(buffer, buffer_size + 1);
            if(temp_buffer == NULL)
            {
                fprintf(stderr, "realloc failed\n");
                *error = 1;
                return NULL;
            }
            buffer = temp_buffer;
        }

        nread = read(fd, buffer + tread, CHUNK_SIZE);
        if(nread == -1)
        {
            if(errno == EAGAIN)
            {
                continue;
            }
            free(buffer);
            *error = 1;
            return NULL;
        }
        tread += (size_t)nread;
        // printf("tread: %zu\n", tread);
        buffer[tread] = '\0';
    } while(check_complete(buffer, tread) == 0);
    return buffer;
}

static int check_complete(char *buffer, size_t buffer_len)
{
    const char *needle     = "\r\n\r\n";
    size_t      needle_len = 4;    // Length of "\r\n\r\n"

    if(memmem(buffer, buffer_len, needle, needle_len) != NULL)
    {
        return 1;    // Found
    }
    return 0;    // Not found
}

static int validate_request(char *request, struct request_params *params)
{
    const char *first_line_end;

    first_line_end = strstr(request, "\r\n");
    if(first_line_end)
    {
        int ret;
        // int         extract_res;
        int         validate_method_res;
        char       *first_line;
        char       *method;
        char       *path;
        const char *version;
        const char *delimiter = " ";
        char       *save_ptr;

        // Extract the first line from the request
        size_t first_line_len = (size_t)(first_line_end - request);
        first_line            = (char *)malloc(first_line_len + 1);
        strncpy(first_line, request, first_line_len);
        first_line[first_line_len] = '\0';
        ret                        = 0;

        // Extract method, path, version from first line
        method  = strtok_r(first_line, delimiter, &save_ptr);
        path    = strtok_r(NULL, delimiter, &save_ptr);
        version = strtok_r(NULL, delimiter, &save_ptr);

        // if(extract_res < 3 || strlen(path) > MAX_PATH_LENGTH)    // if extracted less than 3 parts or path too long
        if(method == NULL || path == NULL || version == NULL || strlen(method) > MAX_METHOD_LENGTH || strlen(path) > MAX_PATH_LENGTH || strlen(version) > MAX_HTTP_VERSION_LENGTH)
        {
            ret = BAD_REQUEST;
            goto end;
        }

        // printf("%s\n", method);
        // printf("%s\n", path);
        // printf("%s\n\n", version);

        if(validate_http_version(version))    // check http version is 1.0
        {
            ret = HTTP_VERSION_NOT_SUPPORTED;
            goto end;
        }

        printf("Version ok\n");    // debug statement

        validate_method_res = validate_http_method(method);    // check if the request parameters are valid
        if(validate_method_res == 1)
        {
            ret = NOT_IMPLEMENTED;
            goto end;
        }
        if(validate_method_res == 2)
        {
            ret = METHOD_NOT_ALLOWED;
            goto end;
        }

        // If request valid, copy the method and path to the passed in params struct
        strlcpy(params->method, method, sizeof(params->method));
        strlcpy(params->path, path, sizeof(params->path));

    end:
        free(first_line);
        return ret;
    }
    return BAD_REQUEST;
}

static int validate_http_version(const char *version)
{
    if(strcmp(version, "HTTP/1.0") != 0 && strcmp(version, "HTTP/1.1") != 0)
    {
        return 1;
    }
    return 0;
}

static int validate_http_method(const char *method)
{
    if(strcmp(method, "GET") == 0 || strcmp(method, "HEAD") == 0 || strcmp(method, "POST") == 0)
    {
        return 0;
    }
    if(strcmp(method, "POST") == 0 || strcmp(method, "PUT") == 0 || strcmp(method, "DELETE") == 0 || strcmp(method, "OPTIONS") == 0 || strcmp(method, "TRACE") == 0 || strcmp(method, "CONNECT") == 0)
    {
        return 2;
    }
    return 1;
}

static void send_error(int fd, const int code)
{
    char  res_buf[ERR_RES_BUF_SIZE];
    char  status[RES_STATUS_BUF_SIZE];
    char *time;
    time = get_time();
    switch(code)    // set status to string depending on what the status code is for the error
    {
        case BAD_REQUEST:
            strcpy(status, "400 Bad Request");
            break;
        case NOT_FOUND:
            strcpy(status, "404 Not found");
            break;
        case METHOD_NOT_ALLOWED:
            strcpy(status, "405 Method Not Allowed");
            break;
        case REQUEST_TIMEOUT:
            strcpy(status, "408 Request Timeout");
            break;
        case HTTP_VERSION_NOT_SUPPORTED:
            strcpy(status, "505 HTTP Version Not Supported");
            break;
        case NOT_IMPLEMENTED:
            strcpy(status, "501 Not Implemented");
            break;
        case FORBIDDEN:
            strcpy(status, "403 Forbidden");
            break;
        case INTERNAL_SERVER_ERROR:
        default:
            strcpy(status, "500 Internal Server Error");
    }

    // format the response
    snprintf(res_buf,
             sizeof(res_buf),
             "HTTP/1.0 %s\r\n"
             "Date: %s\r\n"
             "Server: WL-RL\r\n"
             "Connection: close\r\n\r\n",
             status,
             time);

    // write the error response to the socket
    write_fully(fd, res_buf, strlen(res_buf));

    // free the memory that was allocated in get_time()
    free(time);
}

static char *get_time(void)
{
    const size_t buffer_size = 100;
    time_t       curr_time;
    struct tm    time_gmt;
    char        *time_str;

    time_str = (char *)malloc(buffer_size);

    // get current time and transform into gmt time
    time(&curr_time);
    gmtime_r(&curr_time, &time_gmt);

    // format time into http/1.0 compliant format
    strftime(time_str, buffer_size, "%a, %d %b %Y %H:%M:%S GMT", &time_gmt);
    return time_str;
}

static void handle_request(int fd, char *path, const int is_get)
{
    int         file_fd;
    int         err;
    const char *mime_type;
    off_t       resource_size;
    int         send_200_result;

    err = 0;

    // if extract path is over path limit, send 400 bad request
    if(strlen(path) > MAX_PATH_LENGTH)
    {
        send_error(fd, BAD_REQUEST);
        return;
    }

    // check path for parent directory traversals - not allowed
    if(strstr(path, "/.."))
    {
        send_error(fd, BAD_REQUEST);
        return;
    }

    file_fd = open_resource(path, &err);
    if(file_fd == -1)
    {
        if(err == ENOENT || err == ENOTDIR)    // file doesnt exist on server
        {
            send_error(fd, NOT_FOUND);
        }
        else if(err == EACCES)
        {
            send_error(fd, FORBIDDEN);
        }
        else    // it was a server error e.g. open() failed for other reasons
        {
            send_error(fd, INTERNAL_SERVER_ERROR);
        }
        return;
    }
    // printf("fd: %d\n", file_fd);
    mime_type     = get_mime_type(path);           // retrieves the appropriate value for content-type based on file path
    resource_size = get_resource_size(file_fd);    // retrieves size of the resource
    printf("type: %s, %s, size: %lld\n", mime_type, path, (long long)resource_size);
    if(resource_size == -1)
    {
        send_error(fd, INTERNAL_SERVER_ERROR);
        goto close_fd;
    }

    if(is_get)
    {
        send_200_result = send_200_res(&fd, &file_fd, mime_type, resource_size);
    }
    else
    {
        send_200_result = send_200_res(&fd, NULL, mime_type, resource_size);
    }
    if(send_200_result)
    {
        fprintf(stderr, "Error sending 200 response\n");
    }

close_fd:
    close(file_fd);
}

static int open_resource(char *path, int *err)
{
    int         fd;
    char        full_path[MAX_FULL_PATH_LENGTH];
    struct stat st;
    // append request path to server root
    snprintf(full_path, MAX_FULL_PATH_LENGTH, "%s%s", ROOT, path);

    printf("%s\n", full_path);

    fd = open(full_path, O_RDONLY | O_CLOEXEC);
    if(fd == -1)
    {
        printf("inside\n");
        printf("errno: %d\n", errno);
        if(errno == ENOENT || errno == ENOTDIR)    // resource doesnt exist
        {
            printf("ENOENT\n");
            *err  = errno;
            errno = 0;
            return -1;
        }
        *err  = errno;
        errno = 0;
        return -1;
    }
    if(fstat(fd, &st))
    {
        perror("fstat error-");
        close(fd);
        return -1;
    }

    if(S_ISDIR(st.st_mode))
    {
        close(fd);
        snprintf(full_path, MAX_FULL_PATH_LENGTH, "%s%s%s", ROOT, path, "/index.html");
        // try to open the index.html of the directory
        fd = open(full_path, O_RDONLY | O_CLOEXEC);
        if(fd == -1)
        {
            perror("error opening resource -");
            if(errno == ENOENT)
            {
                *err = EACCES;
            }
            else
            {
                *err = errno;
            }
            return -1;
        }
    }
    strlcpy(path, full_path, MAX_FULL_PATH_LENGTH);    // copy the full path to the path variable so it is accessible in caller scope
    return fd;
}

static int send_200_res(const int *sock_fd, const int *file_fd, const char *mime_type, off_t resource_len)
{
    char *time;
    char  res_buf[OK_RES_HEADER_BUF_SIZE];
    int   ret;

    ret  = 0;
    time = get_time();
    snprintf(res_buf,
             OK_RES_HEADER_BUF_SIZE,
             "HTTP/1.0 200 OK\r\n"
             "Date: %s\r\n"
             "Server: WL-RL\r\n"
             "Connection: close\r\n"
             "Content-Type: %s\r\n"
             "Content-Length: %lld\r\n\r\n",
             time,
             mime_type,
             (long long)resource_len);

    // printf("Res: %s", res_buf);

    if(write_fully(*sock_fd, res_buf, strlen(res_buf)) != 0)
    {
        ret = 1;
        goto end;
    }

    if(file_fd != NULL)
    {
        if(copy(*sock_fd, *file_fd))
        {
            fprintf(stderr, "error copying resource contents to socket\n");
            ret = 1;
        }
    }

end:
    free(time);
    return ret;
}

static void url_decode(char *input)
{
    const int HEX = 16;
    char      decoded[MAX_PATH_LENGTH];
    char     *output = decoded;    // Get a pointer to do pointer arithmetic
    char     *input_dupe;

    input_dupe = input;

    // Decode the input
    while(*input)
    {
        // if encountered character is % - indicating encoded char
        if(*input == '%')
        {
            // Handle percent-encoded characters
            const char hex[3] = {input[1], input[2], '\0'};
            *output++         = (char)strtol(hex, NULL, HEX);    // Convert hex to char
            input += 3;                                          // move 3 spots (skip the hex number that was part of the encoding)
        }
        else
        {
            // If not encoded just copy the character
            *output++ = *input++;
        }
    }
    *output = '\0';    // Null-terminate the decoded string

    // Copy the decoded result back to the input buffer
    strlcpy(input_dupe, decoded, MAX_PATH_LENGTH);
}

static void trim_queries(const char *path)
{
    char *question_mark_pos;

    question_mark_pos = strchr(path, '?');

    if(question_mark_pos != NULL)
    {
        *question_mark_pos = '\0';
    }
}
