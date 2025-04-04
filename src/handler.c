#include "../include/handler.h"
#include "../include/db.h"
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

#define DB_URL "/database"
#define DB_NAME "storage"
#define POST_SUCCESS_MSG "Success"

static int   handle_connection(int fd, sem_t *sem);
static char *read_request(int fd, int *error);
static int   check_complete(char *buffer, size_t buffer_len);
static void  send_error(int fd, int code);
static int   validate_request(char *request, struct request_params *params);
static int   validate_http_method(const char *method, struct request_params *params);
static int   validate_http_version(const char *version);
static char *get_time(void);
static int   handle_retrieval_request(int fd, char *path, int is_get, sem_t *sem);
static int   open_resource(char *path, int *err);
static int   send_200_res(const int *sock_fd, const int *file_fd, const char *mime_type, off_t resource_len, const char *plaintext_msg);
static void  url_decode(char *input);
static int   check_file_exists(char *path, int *err);
int          handle_db_post(int fd, const char *request, sem_t *sem);
int          get_content_length(const char *request, int *content_length);
int          get_key_value(char *key_line, char *val, const char *key_name);
int          handle_request(int fd, char *path, int method, const char *full_request, sem_t *sem);
int          handle_post_request(int fd, char *path, const char *request, sem_t *sem);
int          handle_db_get_head(char *query_params, int is_get, int fd, sem_t *sem);
int          write_to_db(const char *key, const char *val);
char        *read_from_db(const char *key, int *is_db_error);
char        *extract_path_query(char *path, char *query_params);

int handler(int client_fd, sem_t *sem)
{
    int ret;
    printf("======================\nWorker with pid %d handling request\n\n", getpid());
    ret = handle_connection(client_fd, sem);
    close(client_fd);
    return ret;
}

static int handle_connection(int fd, sem_t *sem)
{
    char                 *request;
    int                   err;
    int                   validate_res;
    struct request_params params;
    int                   ret;

    ret = 0;
    // set socket connection to nonblocking so we can implement a time-out mechanism
    if(set_socket_nonblock(fd, &err))
    {
        fprintf(stdout, "Error setting socket to non-blocking - %s\n", strerror(err));
        send_error(fd, INTERNAL_SERVER_ERROR);
        return 1;
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
    printf("%s\n\n", request);

    validate_res = validate_request(request, &params);
    if(validate_res)
    {
        send_error(fd, validate_res);
        goto fail_validate;
    }
    // trim_queries(params.path);    // trims any query arguments from the path as server does not need them

    // Run same method with different flag depending on GET or HEAD request
    ret = handle_request(fd, params.path, params.method_code, request, sem);

fail_validate:
    free(request);
end:
    return ret;
}

int handle_request(int fd, char *path, int method, const char *full_request, sem_t *sem)
{
    int ret;
    ret = 0;
    switch(method)
    {
        case METHOD_GET:
        case METHOD_HEAD:
            ret = handle_retrieval_request(fd, path, method, sem);
            break;
        case METHOD_POST:
            ret = handle_post_request(fd, path, full_request, sem);
            break;
        default:
            fprintf(stderr, "error: handle_request reached default\n");
    }
    return ret;
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

        nread = read(fd, buffer + tread, 1);
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

        if(validate_http_version(version))    // check http version is 1.0/1.1
        {
            ret = HTTP_VERSION_NOT_SUPPORTED;
            goto end;
        }

        printf("Version ok\n");    // debug statement

        validate_method_res = validate_http_method(method, params);    // check if the request parameters are valid
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

static int validate_http_method(const char *method, struct request_params *params)
{
    if(strcmp(method, "GET") == 0)
    {
        params->method_code = METHOD_GET;
        return 0;
    }
    if(strcmp(method, "HEAD") == 0)
    {
        params->method_code = METHOD_HEAD;
        return 0;
    }
    if(strcmp(method, "POST") == 0)
    {
        params->method_code = METHOD_POST;
        return 0;
    }
    if(strcmp(method, "PUT") == 0 || strcmp(method, "DELETE") == 0 || strcmp(method, "OPTIONS") == 0 || strcmp(method, "TRACE") == 0 || strcmp(method, "CONNECT") == 0)
    {
        return 2;
    }
    return 1;
}

static void send_error(int fd, const int code)
{
    char  res_buf[ERR_RES_BUF_SIZE];
    char  status[RES_STATUS_BUF_SIZE];
    char  msg[RES_STATUS_BUF_SIZE] = {0};
    char *time;
    time = get_time();
    switch(code)    // set status to string depending on what the status code is for the error
    {
        case BAD_REQUEST:
            strcpy(status, "400 Bad Request");
            strlcpy(msg, "Bad Request", RES_STATUS_BUF_SIZE);
            break;
        case DB_NOT_FOUND:
            strcpy(status, "404 Not found");
            strlcpy(msg, "No Database Entry", RES_STATUS_BUF_SIZE);
            break;
        case NOT_FOUND:
            strcpy(status, "404 Not found");
            strlcpy(msg, "Not Found", RES_STATUS_BUF_SIZE);
            break;
        case METHOD_NOT_ALLOWED:
            strcpy(status, "405 Method Not Allowed");
            strlcpy(msg, "Method Not Allowed", RES_STATUS_BUF_SIZE);
            break;
        case REQUEST_TIMEOUT:
            strcpy(status, "408 Request Timeout");
            strlcpy(msg, "Request Timed Out", RES_STATUS_BUF_SIZE);
            break;
        case HTTP_VERSION_NOT_SUPPORTED:
            strcpy(status, "505 HTTP Version Not Supported");
            strlcpy(msg, "HTTP Version Not Supported", RES_STATUS_BUF_SIZE);
            break;
        case NOT_IMPLEMENTED:
            strcpy(status, "501 Not Implemented");
            strlcpy(msg, "Method Not Implemented", RES_STATUS_BUF_SIZE);
            break;
        case FORBIDDEN:
            strcpy(status, "403 Forbidden");
            strlcpy(msg, "Forbidden", RES_STATUS_BUF_SIZE);
            break;
        case INTERNAL_SERVER_ERROR:
        default:
            strcpy(status, "500 Internal Server Error");
            strlcpy(msg, "Internal Server Error", RES_STATUS_BUF_SIZE);
    }

    // format the response
    snprintf(res_buf,
             sizeof(res_buf),
             "HTTP/1.0 %s\r\n"
             "Date: %s\r\n"
             "Server: WL-RL\r\n"
             "Content-length: %zu\r\n"
             "Connection: close\r\n\r\n"
             "%s",
             status,
             time,
             strlen(msg),
             msg);

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

static int handle_retrieval_request(int fd, char *path, const int is_get, sem_t *sem)
{
    int   file_fd;
    int   err;
    char *mime_type;
    off_t resource_size;
    int   send_200_result;
    char *query_params;
    int   ret;

    err          = 0;
    ret          = 0;
    query_params = NULL;

    // if extract path is over path limit, send 400 bad request
    if(strlen(path) > MAX_PATH_LENGTH)
    {
        send_error(fd, BAD_REQUEST);
        return 0;
    }

    query_params = extract_path_query(path, query_params);

    if(strcmp(path, DB_URL) == 0)
    {
        int db_res;
        db_res = handle_db_get_head(query_params, is_get, fd, sem);
        if(db_res == 1)
        {
            return 1;
        }
        return 0;
    }

    // check path for parent directory traversals - not allowed
    if(strstr(path, "/.."))
    {
        send_error(fd, BAD_REQUEST);
        return 0;
    }

    url_decode(path);    // Decodes the path if it is encoded

    file_fd = open_resource(path, &err);
    if(file_fd == -1)
    {
        if(err == ENOENT || err == ENOTDIR)    // file doesnt exist on server
        {
            send_error(fd, NOT_FOUND);
            return 0;
        }
        if(err == EACCES)
        {
            send_error(fd, FORBIDDEN);
            return 0;
        }
        // it was a server error e.g. open() failed for other reasons
        send_error(fd, INTERNAL_SERVER_ERROR);
        return 1;
    }
    // printf("fd: %d\n", file_fd);
    mime_type     = get_mime_type(path);           // retrieves the appropriate value for content-type based on file path
    resource_size = get_resource_size(file_fd);    // retrieves size of the resource
    printf("type: %s, %s, size: %lld\n", mime_type, path, (long long)resource_size);
    if(resource_size == -1)
    {
        send_error(fd, INTERNAL_SERVER_ERROR);
        return 1;
    }

    if(is_get)
    {
        send_200_result = send_200_res(&fd, &file_fd, mime_type, resource_size, NULL);
    }
    else
    {
        send_200_result = send_200_res(&fd, NULL, mime_type, resource_size, NULL);
    }
    if(send_200_result)
    {
        fprintf(stderr, "Error sending 200 response\n");
        ret = 1;
    }
    if(fd != -1)
    {
        close(fd);
    }
    free(mime_type);
    return ret;
}

int handle_post_request(int fd, char *path, const char *request, sem_t *sem)
{
    int  err;
    char full_path[MAX_FULL_PATH_LENGTH];

    printf("Handling POST\n");
    // if extract path is over path limit, send 400 bad request
    if(strlen(path) > MAX_PATH_LENGTH)
    {
        printf("Request over max length\n");
        send_error(fd, BAD_REQUEST);
        return 0;
    }

    // check path for parent directory traversals - not allowed
    if(strstr(path, "/.."))
    {
        send_error(fd, BAD_REQUEST);
        return 0;
    }

    if(strcasecmp(path, DB_URL) == 0)
    {
        int db_res;
        db_res = handle_db_post(fd, request, sem);
        if(db_res == 1)
        {
            return 1;
        }
        return 0;
    }

    snprintf(full_path, MAX_FULL_PATH_LENGTH, "%s%s", ROOT, path);
    if(check_file_exists(full_path, &err) == 0)
    {    // not the db path, check to return 404 or 405
        if(err == ENOENT)
        {
            send_error(fd, NOT_FOUND);
            return 0;
        }
        if(err == EACCES)
        {
            fprintf(stderr, "path: %s - %s", full_path, strerror(errno));
            send_error(fd, FORBIDDEN);
            return 0;
        }
        send_error(fd, INTERNAL_SERVER_ERROR);
        return 1;
    }
    send_error(fd, METHOD_NOT_ALLOWED);
    // check if file exists
    return 0;
}

int handle_db_post(int fd, const char *request, sem_t *sem)
{
    int   content_length;
    int   get_content_length_res;
    char *save_ptr;
    char  payload_buf[POST_MAX_PAYLOAD + 1];
    char *key_line;
    char *val_line;
    char  key[POST_MAX_PAYLOAD];
    char  val[POST_MAX_PAYLOAD];
    int   write_res;

    printf("DB POST\n");

    get_content_length_res = get_content_length(request, &content_length);
    if(get_content_length_res == 1)
    {
        printf("failed get content length\n");
        goto bad_req;
    }
    if(get_content_length_res == -1)
    {
        send_error(fd, INTERNAL_SERVER_ERROR);
        return 1;    // server error
    }

    if(read_fully(fd, payload_buf, (size_t)content_length) == -1)
    {
        send_error(fd, INTERNAL_SERVER_ERROR);
        return 1;    // server error
    }

    payload_buf[content_length] = '\0';    // nul terminate

    key_line = strtok_r(payload_buf, "&", &save_ptr);
    val_line = save_ptr;

    if(val_line == NULL)
    {
        goto bad_req;
    }

    if(get_key_value(key_line, key, "key") || get_key_value(val_line, val, "value"))
    {
        goto bad_req;
    }

    sem_wait(sem);
    write_res = write_to_db(key, val);
    sem_post(sem);
    if(write_res)
    {
        send_error(fd, INTERNAL_SERVER_ERROR);
        return 1;
    }
    send_200_res(&fd, NULL, "text/plain", strlen(POST_SUCCESS_MSG), POST_SUCCESS_MSG);
    return 0;
bad_req:
    send_error(fd, BAD_REQUEST);
    return 0;
}

int write_to_db(const char *key, const char *val)
{
    DBM *db;
    char db_name[BUFSIZ];
    int  write_res;

    memcpy(db_name, DB_NAME, strlen(DB_NAME) + 1);

    db = dbm_open(db_name, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if(!db)
    {
        return 1;    // error opening database
    }

    write_res = store_string(db, key, val);

    dbm_close(db);
    printf("Wrote | key: %s, value: %s | to db \n", key, val);
    return write_res;
}

char *read_from_db(const char *key, int *is_db_error)
{
    DBM  *db;
    char *return_val;
    char  db_name[BUFSIZ];

    memcpy(db_name, DB_NAME, strlen(DB_NAME) + 1);

    return_val = NULL;
    db         = dbm_open(db_name, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if(!db)
    {
        *is_db_error = 1;
        return NULL;    // error opening database
    }

    return_val = retrieve_string(db, key);

    dbm_close(db);

    return return_val;
}

int handle_db_get_head(char *query_params, int is_get, int fd, sem_t *sem)
{
    char  keyval[POST_MAX_PAYLOAD];
    char *retrieved_val;
    int   db_error;
    db_error = 0;

    if(!query_params)
    {
        send_error(fd, BAD_REQUEST);
        return 0;
    }

    if(get_key_value(query_params, keyval, "key"))
    {
        printf("Client sent invalid query params for DB GET\n");
        send_error(fd, BAD_REQUEST);
        return 0;
    }

    url_decode(keyval);

    sem_wait(sem);
    retrieved_val = read_from_db(keyval, &db_error);
    sem_post(sem);
    if(!retrieved_val)
    {
        if(db_error)
        {
            fprintf(stderr, "error retrieving from db\n");
            send_error(fd, INTERNAL_SERVER_ERROR);
            return 1;
        }
        send_error(fd, DB_NOT_FOUND);    // No value stored in DB with this key
        return 0;
    }

    if(is_get)
    {
        send_200_res(&fd, NULL, "text/plain", (off_t)strlen(retrieved_val), retrieved_val);
    }
    else
    {
        send_200_res(&fd, NULL, "text/plain", (off_t)strlen(retrieved_val), NULL);
    }

    free(retrieved_val);
    return 0;
}

int get_key_value(char *key_line, char *val, const char *key_name)
{
    char       *save_ptr;
    const char *keykey;
    char       *keyval;

    keykey = strtok_r(key_line, "=", &save_ptr);
    keyval = strtok_r(NULL, "=", &save_ptr);
    if(strcasecmp(keykey, key_name) != 0 || keyval == NULL)
    {
        return 1;    // invalid payload
    }
    strlcpy(val, keyval, POST_MAX_PAYLOAD);
    return 0;
}

int get_content_length(const char *request, int *content_length)
{
    const int SERVER_ERROR = -1;
    const int BAD_REQ      = 1;
    const int BASE_TEN     = 10;

    char *req_dupe;
    char *line;
    char *save_ptr;
    char *end_ptr;
    long  cl;
    req_dupe = strdup(request);
    if(req_dupe == NULL)
    {
        fprintf(stderr, "failed to dupe request\n");
        return SERVER_ERROR;
    }

    to_lowercase(req_dupe);

    strtok_r(req_dupe, "\r\n", &save_ptr);    // method, uri, version line, not needed

    while((line = strtok_r(NULL, "\r\n", &save_ptr)))
    {
        if(strstr(line, "content-length:"))
        {
            break;
        }
    }

    if(line == NULL)
    {
        free(req_dupe);
        return BAD_REQ;
    }
    printf("line: %s\n", line);

    line += strlen("content-length: ");    // move pointer past header;

    cl = strtol(line, &end_ptr, BASE_TEN);
    if(*end_ptr != '\0' || cl > POST_MAX_PAYLOAD)
    {
        free(req_dupe);
        return BAD_REQ;
    }
    *content_length = (int)cl;
    free(req_dupe);
    return 0;
}

static int check_file_exists(char *path, int *err)
{
    struct stat st;

    if(stat(path, &st))
    {
        printf("path: %s\n", path);
        *err = errno;
        return 0;
    }
    return 1;
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
        // printf("errno: %d\n", errno);
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
            // perror("error opening resource -");
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

// plaintext msg parameter only used if the payload is meant to be a plaintext message (only really used for post responses)
static int send_200_res(const int *sock_fd, const int *file_fd, const char *mime_type, off_t resource_len, const char *plaintext_msg)
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
             "Content-Length: %lld\r\n\r\n"
             "%s",
             time,
             mime_type,
             (long long)resource_len,
             plaintext_msg ? plaintext_msg : "");

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

char *extract_path_query(char *path, char *query_params)
{
    char *save_ptr;

    strtok_r(path, "?", &save_ptr);
    query_params = strtok_r(NULL, "?", &save_ptr);

    return query_params;
}
