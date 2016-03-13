#ifndef M_SHA1_H
#define M_SHA1_H

#include <stdint.h>

struct mlb_sha1_hash_t
{
    uint32_t h[5];
};

struct mlb_sha1_hash_context_t
{
    char buf[64];
    size_t buf_idx;
    struct mlb_sha1_hash_t hash;
};

void
mlb_sha1_hash_init(struct mlb_sha1_hash_context_t *context);

void
mlb_sha1_hash_update(struct mlb_sha1_hash_context_t *, const void *, size_t);

struct mlb_sha1_hash_t
mlb_sha1_hash_finalize(struct mlb_sha1_hash_context_t *);

struct mlb_sha1_hash_t
mlb_sha1_hash_buffer(const void *data, size_t length);

struct mlb_sha1_hash_t
mlb_sha1_hash_string(const char *string);

#endif

