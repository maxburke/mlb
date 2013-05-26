/*
 * sha1.h / 2013 Max Burke / Public Domain
 *
 * This module provides a SHA1 hash that works on buffers or on strings.
 */

#ifndef MLB_SHA1_H
#define MLB_SHA1_H

#include <stdint.h>

struct mlb_sha1_hash_t
{
    uint32_t h[5];
};

struct mlb_sha1_hash_t
mlb_sha1_hash_buffer(const void *data, size_t length);

struct mlb_sha1_hash_t
mlb_sha1_hash_string(const char *string);

#endif

