/*
 * http_client.h / 2013 Max Burke / Public Domain
 */

#ifndef MLB_HTTP_CLIENT_H
#define MLB_HTTP_CLIENT_H

#include <stddef.h>

enum http_method_t
{
    HTTP_GET,
    HTTP_POST,
    HTTP_PUT,
    HTTP_DELETE
};

enum http_result_code_t
{
    HTTP_CONTINUE = 100,
    HTTP_SWITCHING_PROTOCOLS = 101,
    HTTP_OK = 200,
    HTTP_CREATED = 201,
    HTTP_ACCEPTED = 202,
    HTTP_NON_AUTHORITATIVE_INFORMATION = 203,
    HTTP_NO_CONTENT = 204,
    HTTP_RESET_CONTENT = 205,
    HTTP_PARTIAL_CONTENT = 206,
    HTTP_MULTI_STATUS = 207,
    HTTP_MULTIPLE_CHOICES = 300,
    HTTP_MOVED_PERMANENTLY = 301,
    HTTP_MOVED_TEMPORARILY = 302,
    HTTP_SEE_OTHER = 303,
    HTTP_NOT_MODIFIED = 304,
    HTTP_USE_PROXY = 305,
    HTTP_TEMPORARY_REDIRECT = 307,
    HTTP_BAD_REQUEST = 400,
    HTTP_AUTHORIZATION_REQUIRED = 401,
    HTTP_PAYMENT_REQUIRED = 402,
    HTTP_FORBIDDEN = 403,
    HTTP_NOT_FOUND = 404,
    HTTP_METHOD_NOT_ALLOWED = 405,
    HTTP_NOT_ACCEPTABLE = 406,
    HTTP_PROXY_AUTHENTICATION_REQUIRED = 407,
    HTTP_REQUEST_TIME_OUT = 408,
    HTTP_CONFLICT = 409,
    HTTP_GONE = 410,
    HTTP_LENGTH_REQUIRED = 411,
    HTTP_PRECONDITION_FAILED = 412,
    HTTP_REQUEST_ENTITY_TOO_LARGE = 413,
    HTTP_REQUEST_URI_TOO_LARGE = 414,
    HTTP_UNSUPPORTED_MEDIA_TYPE = 415,
    HTTP_REQUESTED_RANGE_NOT_SATISFIABLE = 416,
    HTTP_EXPECTATION_FAILED = 417,
    HTTP_FAILED_DEPENDENCY = 424,
    HTTP_INTERNAL_SERVER_ERROR = 500,
    HTTP_NOT_IMPLEMENTED = 501,
    HTTP_BAD_GATEWAY = 502,
    HTTP_SERVICE_UNAVAILABLE = 503,
    HTTP_GATEWAY_TIME_OUT = 504,
    HTTP_VERSION_NOT_SUPPORTED = 505
};

struct http_request_handle_t;
struct http_session_t;

typedef void *(*http_alloc_fn)(size_t size);
typedef void (*http_free_fn)(void *ptr);

struct http_session_parameters_t
{
    http_alloc_fn alloc;
    http_free_fn free;
};

struct http_parameter_t
{
    const char *name;
    const char *value;
};

struct http_request_t
{
    const char *url;
    enum http_method_t method;

    int num_get_parameters;
    struct http_parameter_t *get_parameters;

    const char *content_type;
    size_t content_body_length;
    const void *content_body;
};

struct http_result_t
{
    enum http_result_code_t result;
    size_t data_size;
    char *data;
    char *content_type;
};

/*
 * Creates a new session. A session encapsulates the parameters desired by
 * the user of this library (ie: memory allocation) plus all settings 
 * accumulated during this session, such as cookies.
 */
struct http_session_t *
http_session_create(struct http_session_parameters_t *session_parameters);

/*
 * This function adds a key/value POST parameter pair to the body of the
 * provided request buffer. This function performs a URL encoding operation
 * on the keys and values. The buffer pointer must point to the start of where
 * the parameter should be written, not the start of the buffer.
 *
 * This function returns the number of bytes required to encode the given
 * key/value pair. If the buffer isn't big enough, no data will be written.
 *
 * The result of this function is null terminated.
 *
 * Using this method usually requires that the content_type of the request
 * be set to application/x-www-form-urlencoded.
 */
size_t
http_add_post_parameter_to_body(char *buffer, size_t buffer_size, struct http_parameter_t parameter);

/*
 * Initiate a request as detailed by the given http_request_t object.
 */
struct http_request_handle_t *
http_request_begin(struct http_session_t *session, struct http_request_t *request);

/*
 * Performs a blocking wait for the completion of the request. This function
 * must have been passed the address of a valid http_result_t structure.
 */
void
http_request_wait(struct http_request_handle_t *request, struct http_result_t *result);

/*
 * Check to see if the result has completed. This function must have be passed
 * the address of a valid http_result_t structure. If the request has completed
 * this result structure will be populated with the results of the current 
 * request. If the request has not completed, the result structure will be 
 * zeroed.
 *
 * Returns 0 if the request has not yet completed or 1 if it has.
 */
int
http_request_iterate(struct http_request_handle_t *request, struct http_result_t *result);

/*
 * Dispose of the request handle after the request has finished.
 */
void
http_request_end(struct http_request_handle_t *request);

/*
 * Destroy the session and release all resources associated with it.
 */
void
http_session_destroy(struct http_session_t *session);

#endif

