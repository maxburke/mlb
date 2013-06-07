/*
 * mlb_test.c / 2013 Max Burke / Public Domain
 */

#include "mlb_arg_parse.h"
#include "mlb_sha1.h"

/*
 * Normally my coding style has the standard include files come before the
 * local library include files, but here it's reversed so that I can see 
 * if I am forgetting any inclusions in the library header files.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int arg_tests_failed;

#define ARG_TEST_ASSERT(cond) if (!(cond)) { printf("%s(%d): FAILED - %s\n", __FILE__, __LINE__, #cond); ++arg_tests_failed; } else (void)0

static void
parameter_callback(void *context, const struct mlb_arg_t *arg, const char *value)
{
    ARG_TEST_ASSERT(context == NULL);
    ARG_TEST_ASSERT(strcmp(arg->short_form, "-O") == 0 && strcmp(arg->long_form, "--optimize") == 0);
    ARG_TEST_ASSERT(strcmp(value, "2") == 0 && strlen(value) == 1);
    ARG_TEST_ASSERT(arg != NULL);
    ARG_TEST_ASSERT(arg->type == ARG_TYPE_PARAMETER);
}

static void
positional_callback(void *context, const struct mlb_arg_t *arg, const char *value)
{
    static int invocation;

    ARG_TEST_ASSERT(context == NULL);
    ARG_TEST_ASSERT(arg != NULL);
    ARG_TEST_ASSERT(arg->type == ARG_TYPE_POSITIONAL);
    ARG_TEST_ASSERT(value != NULL);

    switch (invocation++)
    {
        case 0:
            ARG_TEST_ASSERT(strcmp(value, "test.c") == 0);
            break;
        case 1:
            ARG_TEST_ASSERT(strcmp(value, "foobar.c") == 0);
            break;
    }
}

static void
switch_callback(void *context, const struct mlb_arg_t *arg, const char *value)
{
    static int invocation;

    ARG_TEST_ASSERT(context == NULL);
    ARG_TEST_ASSERT(value == NULL);
    ARG_TEST_ASSERT(arg != NULL);
    ARG_TEST_ASSERT(arg->type == ARG_TYPE_SWITCH);

    switch (invocation++)
    {
        case 0:
        case 2:
            ARG_TEST_ASSERT(
                    strcmp(arg->short_form, "-h") == 0
                        && strcmp(arg->long_form, "--help") == 0);
            break;
        case 1:
        case 3:
            ARG_TEST_ASSERT(
                    strcmp(arg->short_form, "-v") == 0 
                        && strcmp(arg->long_form, "--verbose") == 0);
            break;
    }
}

static int
test_arg_parse(void)
{
    static struct mlb_arg_t test_args[] = 
    {
        { "-h", "--help", ARG_TYPE_SWITCH, switch_callback },
        { "-v", "--verbose", ARG_TYPE_SWITCH, switch_callback },
        { "-O", "--optimize", ARG_TYPE_PARAMETER, parameter_callback }
    };
    static char *argv[] = 
    {
        "mlb.exe",
        "-h",
        "-v",
        "--help",
        "--verbose",
        "-O2",
        "--optimize",
        "2",
        "--optimize=2",
        "test.c",
        "foobar.c"
    };
    static int argc = (int)(sizeof argv / sizeof argv[0]);
    struct mlb_arg_context_t arg_context = 
    {
        argc,
        argv,
        NULL,
        sizeof test_args / sizeof test_args[0],
        test_args,
        positional_callback
    };

    mlb_arg_parse(&arg_context);

    return arg_tests_failed;
}

static int
test_hash(struct mlb_sha1_hash_t hash, uint32_t e0, uint32_t e1, uint32_t e2, uint32_t e3, uint32_t e4)
{
    return !(hash.h[0] == e0 && hash.h[1] == e1 && hash.h[2] == e2 && hash.h[3] == e3 && hash.h[4] == e4);
}

static int
test_sha1(void)
{
    int result;
    struct mlb_sha1_hash_t hash;

    hash = mlb_sha1_hash_string("");
    result = test_hash(hash, 0xda39a3ee, 0x5e6b4b0d, 0x3255bfef, 0x95601890, 0xafd80709);

    hash = mlb_sha1_hash_string("The quick brown fox jumps over the lazy dog");
    result += test_hash(hash, 0x2fd4e1c6, 0x7a2d28fc, 0xed849ee1, 0xbb76e739, 0x1b93eb12);

    return result;
}

int
main(void)
{
    int tests_failed;

    tests_failed  = test_arg_parse();
    tests_failed += test_sha1();

    printf("%d tests failed", tests_failed);
    return tests_failed;
}

