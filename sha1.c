/*
 * sha1.c / 2013 Max Burke / Public Domain
 *
 * This module provides a SHA1 hash that works on buffers or on strings.
 *
 * You will need to define one of the symbols BIG_ENDIAN or LITTLE_ENDIAN
 * for this to build.
 */

#ifdef _MSC_VER
#pragma warning(push, 0)
#endif

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#include "sha1.h"

#if !defined(__STDC_VERSION__) || __STDC_VERSION__ < 199901L
    #define inline
#endif

union uint64_to_bytes_t
{
    uint64_t u8;
    char bytes[8];
};

#ifdef LITTLE_ENDIAN
    static inline uint32_t
    u32_to_big_endian(uint32_t p)
    {
        return ((p & 0x000000FF) << 24)
            | ((p & 0x0000FF00) << 8)
            | ((p & 0x00FF0000) >> 8)
            | ((p & 0xFF000000) >> 24);
    }

    static inline void
    write_length(char *ptr, uint64_t length)
    {
        union uint64_to_bytes_t c8;
        size_t i;

        length <<= 3;
        c8.u8 = length;

        for (i = 0; i < sizeof c8.bytes; ++i)
        {
            *ptr++ = c8.bytes[(sizeof c8.bytes) - i - 1];
        }
    }
#endif

#ifdef BIG_ENDIAN
    #define u32_to_big_endian(x) (x)

    static inline void
    write_length(char *ptr, uint64_t length)
    {
        union uint64_to_bytes_t c8;
        size_t i;

        length <<= 3;
        c8.u8 = length;

        for (i = 0; i < sizeof c8.bytes; ++i)
        {
            *ptr++ = c8.bytes[i];
        }
    }
#endif

static inline uint32_t
left_rotate_1(uint32_t val)
{
    return (val << 1) | (val >> 31);
}

static inline uint32_t
left_rotate_5(uint32_t val)
{
    return (val << 5) | (val >> 27);
}

static inline uint32_t
left_rotate_30(uint32_t val)
{
    return (val << 30) | (val >> 2);
}

static inline size_t
initialize_last_chunk(char last_chunk[128], const void *data, size_t length)
{
    size_t remainder;
    const char *ptr;

    ptr = data;
    remainder = length & 63;
    memmove(last_chunk, ptr + (length & (~63)), remainder);
    last_chunk[remainder] = 0x80;

    if (remainder >= 55)
    {
        write_length(last_chunk + 120, length);
        ptr = last_chunk;
        return 2;
    }

    write_length(last_chunk + 56, length);
    ptr = last_chunk;
    return 1;
}

static inline struct sha1_hash_t
hash_chunk(struct sha1_hash_t h, const void *mem)
{
    uint32_t buf[80];
    int i;
    uint32_t a;
    uint32_t b;
    uint32_t c;
    uint32_t d;
    uint32_t e;
    uint32_t f;
    uint32_t k;
    uint32_t temp;
    const uint32_t *ptr;

    ptr = mem;

    buf[0] = u32_to_big_endian(ptr[0]);
    buf[1] = u32_to_big_endian(ptr[1]);
    buf[2] = u32_to_big_endian(ptr[2]);
    buf[3] = u32_to_big_endian(ptr[3]);
    buf[4] = u32_to_big_endian(ptr[4]);
    buf[5] = u32_to_big_endian(ptr[5]);
    buf[6] = u32_to_big_endian(ptr[6]);
    buf[7] = u32_to_big_endian(ptr[7]);
    buf[8] = u32_to_big_endian(ptr[8]);
    buf[9] = u32_to_big_endian(ptr[9]);
    buf[10] = u32_to_big_endian(ptr[10]);
    buf[11] = u32_to_big_endian(ptr[11]);
    buf[12] = u32_to_big_endian(ptr[12]);
    buf[13] = u32_to_big_endian(ptr[13]);
    buf[14] = u32_to_big_endian(ptr[14]);
    buf[15] = u32_to_big_endian(ptr[15]);

    for (i = 16; i < 80; ++i)
    {
        buf[i] = left_rotate_1((buf[i - 3] ^ buf[i - 8] ^ buf[i - 14] ^ buf[i - 16]));
    }

    a = h.h[0];
    b = h.h[1];
    c = h.h[2];
    d = h.h[3];
    e = h.h[4];

    #define ITERATE() { \
        temp = left_rotate_5(a) + f + e + k + buf[i]; \
        e = d; \
        d = c; \
        c = left_rotate_30(b); \
        b = a; \
        a = temp; \
    }

    k = 0x5a827999;
    for (i = 0; i < 20; ++i)
    {
        f = (b & c) | ((~b) & d);
        ITERATE();
    }

    k = 0x6ed9eba1;
    for (; i < 40; ++i)
    {
        f = b ^ c ^ d;
        ITERATE();
    }

    k = 0x8f1bbcdc;
    for (; i < 60; ++i)
    {
        f = (b & c) | (b & d) | (c & d);
        ITERATE();
    }

    k = 0xca62c1d6;
    for (; i < 80; ++i)
    {
        f = b ^ c ^ d;
        ITERATE();
    }

    h.h[0] = h.h[0] + a;
    h.h[1] = h.h[1] + b;
    h.h[2] = h.h[2] + c;
    h.h[3] = h.h[3] + d;
    h.h[4] = h.h[4] + e;

    return h;
}

struct sha1_hash_t
sha1_hash_buffer(const void *data, size_t length)
{
    char last_chunk[128];
    const char *string;
    size_t i;
    struct sha1_hash_t rv;
    size_t num_chunks;
    size_t num_extra_chunks;

    string = data;

    rv.h[0] = 0x67452301;
    rv.h[1] = 0xefcdab89;
    rv.h[2] = 0x98badcfe;
    rv.h[3] = 0x10325476;
    rv.h[4] = 0xc3d2e1f0;

    num_chunks = length / 64;
    memset(last_chunk, 0, sizeof last_chunk);
    num_extra_chunks = initialize_last_chunk(last_chunk, string, length);
    
    for (i = 0; i < num_chunks; ++i)
    {
        rv = hash_chunk(rv, string);
        string += 64;
    }

    string = last_chunk;
    for (i = 0; i < num_extra_chunks; ++i)
    {
        rv = hash_chunk(rv, string);
        string += 64;
    }

    return rv;
}

struct sha1_hash_t
sha1_hash_string(const char *string)
{
    return sha1_hash_buffer(string, strlen(string));
}

