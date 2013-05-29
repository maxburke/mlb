/*
 * mlb_http_client.c / 2013 Max Burke / Public Domain
 */

/*
 * Fair warning, this file is still very much under construction.
 */

#ifdef _MSC_VER
#pragma warning(push, 0)
#endif

#include <assert.h>
#include <stdio.h>
#include <string.h>

#ifdef _MSC_VER
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")
#endif

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#include "mlb_http_client.h"

#ifndef UNUSED
#define UNUSED(x) (void)x
#endif

#ifdef _MSC_VER
#define inline __inline
#define HTTP_ENFORCE(session, x, y) \
    if (!(x))\
    { \
        int error; \
        const char *error_string; \
        error = WSAGetLastError(); \
        error_string = http_get_error_string(error); \
        if (session->error) \
        { \
            session->error(error_string); \
        } \
        else \
        { \
            fprintf(stderr, "[http] error: %s\n", error_string); \
        } \
        return y; \
    }

static const char *
http_get_error_string(int error)
{
    char *error_string;
    
    FormatMessageA(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL,
            error,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            (LPSTR)&error_string,
            0,
            NULL);

    if (!error_string)
    {
        return " -- ERROR -- Unable to retrieve system error message";
    }

    return error_string;
}

#endif

#ifndef _MSC_VER
    typedef int SOCKET;
    #define closesocket close
    #define ioctlsocket ioctl
#endif

static const char http_user_agent[] = "User-Agent: mlbhttp/1.0\x0d\x0a";
static int http_initialized;

enum http_request_state_t
{
    HTTP_REQUEST_STATE_INITIAL,
    HTTP_REQUEST_STATE_READING_HEADER,
    HTTP_REQUEST_STATE_READING_BODY,
    HTTP_REQUEST_STATE_COMPLETE
};

#define HEADER_BUFFER_SIZE 4096

struct http_request_handle_t
{
    struct http_session_t *session;
    struct http_url_t url;
    enum http_method_t method;
    const char *content_type;
    size_t content_body_size;
    const char *content_body;

    enum http_request_state_t state;
    size_t idx;

    char *header_buffer;
    size_t header_buffer_size;

    char *response_body;
    size_t response_body_size;

    char *response_content_type;
    enum http_result_code_t result;

    SOCKET request_socket;
};

struct http_session_t
{
    http_alloc_fn alloc;
    http_free_fn free;
    http_error_fn error;
};

static void
http_initialize(void)
{
#ifdef _MSC_VER
    WSADATA wsa_data;
    int result;

    if (http_initialized)
    {
        return;
    }

    memset(&wsa_data, 0, sizeof wsa_data);
    result = WSAStartup(MAKEWORD(2, 2), &wsa_data);

    assert(result == 0);

    http_initialized = 1;
#endif
}

struct http_session_t *
http_session_create(struct http_session_parameters_t *session_parameters)
{
    struct http_session_t *session;

    assert(session_parameters != NULL);

    session = session_parameters->alloc(sizeof(struct http_session_t));
    session->alloc = session_parameters->alloc;
    session->free = session_parameters->free;
    session->error = session_parameters->error;

    http_initialize();

    return session;
}

static inline int
must_percent_encode(char c)
{
    return !(((c >= 'A') && (c <= 'Z')) 
        || ((c >= 'a') && (c <= 'z'))
        || ((c >= '0') && (c <= '9'))
        || c == '-' || c == '_' || c == '.' || c == '~');
}

static size_t
http_url_encode_fragment(char *destination, const char *uri)
{
    static const char hex_chars[] = { 
        '0', '1', '2', '3', '4', '5', '6', '7', 
        '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
    };
    static const char lengths[] = {
        3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 6, 3, 3, 3, 3, 3,
        3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
        1, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 1, 1, 3,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 3, 3, 3, 3, 3, 3,
        3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 3, 3, 3, 3, 1,
        3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 3, 3, 3, 1, 3,
        3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
        3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
        3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
        3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
        3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
        3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
        3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
        3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3
    };
    size_t i;
    const char *ptr;
    int write_to_destination;
    char previous_char;
    char c;

    i = 0;
    ptr = uri;
    write_to_destination = destination != NULL;
    previous_char = 0;
    c = 0;

    if (!write_to_destination)
    {
        for (;;)
        {
            unsigned char byte = (unsigned char)*ptr++;
            if (byte == 0)
            {
                break;
            }

            i += lengths[byte];
        }

        return i;
    }

    for (;;)
    {
        previous_char = c;
        c = *ptr++;

        if (c == 0)
        {
            break;
        } 
        else if (c == '\n' && previous_char != '\r')
        {
            memmove(destination, "%0D%0A", 6);
            destination += 6;
            i += 6;
        }
        else if (c == ' ')
        {
            *destination++ = '+';
            ++i;
        }
        else if (must_percent_encode(c))
        {
            int low_nybble;
            int high_nybble;

            low_nybble = (int)c & 0xF;
            high_nybble = ((int)c & 0xF0) >> 4;
            i += 3;

            *destination++ = '%';
            *destination++ = hex_chars[high_nybble];
            *destination++ = hex_chars[low_nybble];
        }
        else
        {
            *destination++ = c;
            ++i;
        }
    }

    return i;
}

static const char *
http_add_get_parameters_to_path(struct http_session_t *session, struct http_request_t *request)
{
    char *encoded_url;
    char *ptr;
    size_t encoded_url_length;
    size_t original_path_length;
    int i;
    int e;
    struct http_parameter_t *get_parameters;
    const char *original_path;

    original_path = request->url.path;
    original_path_length = strlen(original_path);
    encoded_url_length = original_path_length;
    get_parameters = request->get_parameters;

    if (request->num_get_parameters == 0)
    {
        return original_path;
    }

    for (i = 0, e = request->num_get_parameters; i < e; ++i)
    {
        encoded_url_length += 1 + http_url_encode_fragment(NULL, get_parameters[i].name);

        if (get_parameters[i].value != NULL)
        {
            encoded_url_length += 1 + http_url_encode_fragment(NULL, get_parameters[i].value);
        }
    }

    encoded_url = session->alloc(encoded_url_length + 1);
    ptr = encoded_url;

    memmove(ptr, original_path, original_path_length);
    ptr += original_path_length;

    for (i = 0, e = request->num_get_parameters; i < e; ++i)
    {
        *ptr++ = (i == 0) ? '?' : '&';
        ptr += http_url_encode_fragment(ptr, get_parameters[i].name);

        if (get_parameters[i].value != NULL)
        {
            *ptr++ = '=';
            ptr += http_url_encode_fragment(ptr, get_parameters[i].value);
        }
    }

    *ptr++ = 0;

    return encoded_url;
}

size_t
http_add_post_parameter_to_body(char *buffer, size_t buffer_size, struct http_parameter_t parameter)
{
    size_t required_size;
    const char *name;
    const char *value;

    name = parameter.name;
    value = parameter.value;

    required_size = http_url_encode_fragment(NULL, name);
    required_size += 1;
    required_size += http_url_encode_fragment(NULL, value);
    required_size += 2;

    if (required_size < buffer_size && buffer != NULL)
    {
        buffer += http_url_encode_fragment(buffer, name);
        *buffer++ = '=';
        buffer += http_url_encode_fragment(buffer, value);
        *buffer++ = '&';
        *buffer++ = 0;
    }

    return required_size;
}

static SOCKET
http_connection_connect(struct http_request_handle_t *request)
{
    unsigned short port;
    struct addrinfo *result;
    struct addrinfo *i;
    SOCKET socket_handle;
    int success;

    socket_handle = 0;
    success = 0;
    port = request->url.port;
    HTTP_ENFORCE(request->session, getaddrinfo(request->url.authority, NULL, NULL, &result) == 0, INVALID_SOCKET);

    for (i = result; i != NULL; i = i->ai_next)
    {
        socket_handle = socket(i->ai_family, i->ai_socktype, i->ai_protocol);
        HTTP_ENFORCE(request->session, socket_handle != INVALID_SOCKET, INVALID_SOCKET);

        switch (i->ai_addr->sa_family)
        {
            case AF_INET:
                {
                    struct sockaddr_in *s;

                    s = (struct sockaddr_in *)i->ai_addr;
                    s->sin_port = htons(port);
                }
                break;
            case AF_INET6:
                {
                    struct sockaddr_in6 *s;

                    s = (struct sockaddr_in6 *)i->ai_addr;
                    s->sin6_port = htons(port);
                }
                break;
            default:
                assert(0 && "Unknown socket family!");
                break;
        }

        if (connect(socket_handle, i->ai_addr, i->ai_addrlen) == 0)
        {
            success = 1;
            break;
        }
    }

    freeaddrinfo(result);

    if (!success)
    {
        if (socket_handle != 0)
        {
            closesocket(socket_handle);
        }

        return INVALID_SOCKET;
    }

    return socket_handle;
}

static int
http_connection_open(struct http_request_handle_t *request)
{
    int port;
    SOCKET socket_handle;

    socket_handle = http_connection_connect(request);

    if (socket_handle == INVALID_SOCKET)
    {
        return 1;
    }

    port = request->url.port == 0 ? 80 : request->url.port;
    request->request_socket = socket_handle;

    return 0;
}

static void
http_request_send_method(struct http_request_handle_t *handle)
{
    static const char *method_strings[] = 
    {
        "GET ",
        "POST ",
        "PUT ",
        "DELETE "
    };

    static const int method_string_lengths[] = 
    {
        4,
        5,
        4,
        7
    };

    enum http_method_t method;

    method = handle->method;
    assert(method >= HTTP_GET && method < HTTP_NUM_METHODS);

    send(handle->request_socket, method_strings[method], method_string_lengths[method], 0);
}

static void
http_request_send_request(struct http_request_handle_t *handle)
{
    static const char http_version_string[] = " HTTP/1.1\x0d\x0a";
    static const char host_string[] = "Host: ";
    static const char new_line_string[] = "\x0d\x0a";
    SOCKET socket_handle;

    #define send_string(s) send(socket_handle, s, (sizeof s) - 1, 0)

    socket_handle = handle->request_socket;

    http_request_send_method(handle);
    send(socket_handle, handle->url.path, strlen(handle->url.path), 0);
    send_string(http_version_string);
    send_string(host_string);
    send(socket_handle, handle->url.authority, strlen(handle->url.authority), 0);
    send_string(new_line_string);
    send(socket_handle, new_line_string, (sizeof new_line_string) - 1, 0);

    if (handle->content_body_size > 0)
    {
        static const char content_type_string[] = "Content-Type: ";
        static const char content_length_string[] = "Content-Length: ";

        const char *content_type;
        size_t content_length;
        char digits[22];

        content_type = handle->content_type;
        content_length = handle->content_body_size;

        send_string(content_type_string);
        send(socket_handle, content_type, strlen(content_type), 0);
        send_string(new_line_string);
        send_string(content_length_string);
    
        memset(digits, 0, sizeof digits);
        sprintf(digits, "%ul", content_length);
        send(socket_handle, digits, strlen(digits), 0);
        send_string(new_line_string);
        send_string(new_line_string);

        send(socket_handle, handle->content_body, content_length, 0);
    }
    else
    {
        send_string(new_line_string);
    }
}

struct http_request_handle_t *
http_request_begin(struct http_session_t *session, struct http_request_t *request)
{
    struct http_request_handle_t *handle;

    assert(session != NULL);
    assert(request != NULL);

    handle = session->alloc(sizeof(struct http_request_handle_t));
    handle->session = session;
    handle->method = request->method;
    handle->url = request->url;
    handle->url.path = http_add_get_parameters_to_path(session, request);

    if (http_connection_open(handle))
    {
        return NULL;
    }

    http_request_send_request(handle);
    return handle;
}

void
http_request_wait(struct http_request_handle_t *request, struct http_result_t *result)
{
    while (http_request_iterate(request, result) == 0)
        ;
}

static void
http_parse_header(struct http_request_handle_t *request)
{
    (void)request;
    assert(0 && "hello");
}

int
http_request_iterate(struct http_request_handle_t *request, struct http_result_t *result)
{
    assert(request != NULL);
    assert(result != NULL);

    switch (request->state)
    {
        case HTTP_REQUEST_STATE_INITIAL:
            {
                request->header_buffer_size = 0;
                request->state = HTTP_REQUEST_STATE_READING_HEADER;
                request->idx = 0;
            }
        case HTTP_REQUEST_STATE_READING_HEADER:
            {
                unsigned long data_pending_size;
                SOCKET socket_handle;
                int bytes_read;
                size_t current_position;
                static const char end_of_header[] = "\x0d\x0a\x0d\x0a";

                socket_handle = request->request_socket;
                current_position = request->idx;
                ioctlsocket(socket_handle, FIONREAD, &data_pending_size);

                if (data_pending_size == 0)
                {
                    return 0;
                }

                if (data_pending_size + current_position > request->header_buffer_size)
                {
                    size_t new_header_buffer_size;
                    void *new_header_buffer;

                    new_header_buffer_size = request->header_buffer_size + HEADER_BUFFER_SIZE;
                    new_header_buffer = request->session->alloc(new_header_buffer_size);

                    memset(new_header_buffer, 0, new_header_buffer_size);
                    request->header_buffer_size = new_header_buffer_size;
                    request->header_buffer = new_header_buffer;
                }

                bytes_read = recv(socket_handle, request->header_buffer + current_position, data_pending_size, 0);
                assert(bytes_read >= 0 && (size_t)bytes_read == data_pending_size);

                if (strstr(request->header_buffer, end_of_header) == NULL)
                {
                    return 0;
                }

                http_parse_header(request);
            }
            break;
        case HTTP_REQUEST_STATE_READING_BODY:
            {
                assert(0 && "TODO");
            }
            break;
        case HTTP_REQUEST_STATE_COMPLETE:
            {
                result->result = request->result;
                result->response_body_size = request->response_body_size;
                result->response_body = request->response_body;
                result->content_type = request->response_content_type;
                return 1;
            }
        default:
            assert(0 && "Unknown request state!");
            break;
    }

    return 0;
}

void
http_request_end(struct http_request_handle_t *request)
{
    assert(request != NULL);

    UNUSED(request);
}

void
http_session_destroy(struct http_session_t *session)
{
    assert(session != NULL);

    UNUSED(session);
}


