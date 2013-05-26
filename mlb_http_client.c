/*
 * http_client.c / 2013 Max Burke / Public Domain
 */

/*
 * TODO:
 * Use a linear allocator for the http requests.
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

#include "http_client.h"

#ifndef UNUSED
#define UNUSED(x) (void)x
#endif

#ifdef _MSC_VER
#define inline __inline
#define HTTP_ENFORCE(session, x, y) \
    if ((x))\
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
#endif

static const char http_user_agent[] = "User-Agent: mlbhttp/1.0\x0d\x0a";
static int http_initialized;

struct http_request_handle_t
{
    struct http_session_t *session;
    struct http_url_t url;
    enum http_method_t method;
    const char *content_type;
    size_t content_body_size;
    const char *content_body;

    
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
        if (i->ai_socktype != SOCK_STREAM)
        {
            continue;
        }

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

    return 0;
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

    return handle;
}

void
http_request_wait(struct http_request_handle_t *request, struct http_result_t *result)
{
    assert(request != NULL);
    assert(result != NULL);

    UNUSED(request);
    UNUSED(result);
}

int
http_request_iterate(struct http_request_handle_t *request, struct http_result_t *result)
{
    assert(request != NULL);
    assert(result != NULL);

    UNUSED(request);
    UNUSED(result);

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


