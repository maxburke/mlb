/*
 * http_client.c / 2013 Max Burke / Public Domain
 */

#ifdef _MSC_VER
#pragma warning(push, 0)
#endif

#include <assert.h>
#include <string.h>

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#include "http_client.h"

#ifndef UNUSED
#define UNUSED(x) (void)x
#endif

#ifdef _MSC_VER
#define inline __inline
#endif

static const char http_user_agent[] = "User-Agent: mlbhttp/1.0\x0d\x0a";

struct http_request_handle_t
{
    struct http_session_t *session;
    const char *url;
    enum http_method_t method;
    const char *content_type;
    size_t content_body_size;
    const char *content_body;
};

struct http_session_t
{
    http_alloc_fn alloc;
    http_free_fn free;
};

struct http_session_t *
http_session_create(struct http_session_parameters_t *session_parameters)
{
    struct http_session_t *session;

    assert(session_parameters != NULL);

    session = session_parameters->alloc(sizeof(struct http_session_t));
    session->alloc = session_parameters->alloc;
    session->free = session_parameters->free;

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
http_encode_url(struct http_session_t *session, struct http_request_t *request)
{
    char *encoded_url;
    char *ptr;
    size_t encoded_url_length;
    size_t base_url_length;
    int i;
    int e;
    struct http_parameter_t *get_parameters;

    base_url_length = strlen(request->url);
    encoded_url_length = base_url_length;
    get_parameters = request->get_parameters;

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

    memmove(ptr, request->url, base_url_length);

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

struct http_request_handle_t *
http_request_begin(struct http_session_t *session, struct http_request_t *request)
{
    struct http_request_handle_t *handle;

    assert(session != NULL);
    assert(request != NULL);

    handle = session->alloc(sizeof(struct http_request_handle_t));
    handle->session = session;
    handle->method = request->method;
    handle->url = http_encode_url(session, request);

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


