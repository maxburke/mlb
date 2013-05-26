/*
 * mlb_arg_parse.c / 2013 Max Burke / Public Domain
 */

#include <assert.h>
#include <string.h>

#include "mlb_arg_parse.h"

static int
is_short_arg(const char *a)
{
    return a[0] == '-' && (a[1] == 0 || a[1] != '-');
}

static const struct mlb_arg_t *
find_short_arg(const char *arg_string, size_t num_args, const struct mlb_arg_t *args, const char **value)
{
    size_t i;

    for (i = 0; i < num_args; ++i)
    {
        const char *short_form;
        size_t short_form_length;

        short_form = args[i].short_form;

        if (short_form == NULL)
        {
            continue;
        }
        
        short_form_length = strlen(short_form);

        /*
         * Short form arguments have to be 2 chars long, "-c", "-v", etc.
         */
        assert(short_form_length == 2);

        if (strstr(arg_string, short_form) == arg_string)
        {
            if (args[i].type == ARG_TYPE_PARAMETER)
            {
                *value = arg_string + short_form_length;
            }

            return &args[i];
        }
    }

    return NULL;
}

static int
long_arg_equals(const char *arg_string, const char *arg, const char **value)
{
    do
    {
        if (*arg_string == 0 || *arg == 0)
        {
            break;
        }
    } while (*arg_string++ == *arg++);

    if (*arg_string == 0 && *arg == 0)
    {
        return 1;
    }

    if (*arg_string == '=' && *arg == 0)
    {
        *value = arg_string + 1;

        return 1;
    }

    return 0;
}

static const struct mlb_arg_t *
find_long_arg(const char *arg_string, size_t num_args, const struct mlb_arg_t *args, const char **value)
{
    size_t i;

    for (i = 0; i < num_args; ++i)
    {
        if (long_arg_equals(arg_string, args[i].long_form, value))
            return &args[i];
    }

    return NULL;
}

static const struct mlb_arg_t *
find_arg(const char *arg_string, size_t num_args, const struct mlb_arg_t *args, const char **value)
{
    *value = NULL;
    return is_short_arg(arg_string) 
        ? find_short_arg(arg_string, num_args, args, value)
        : find_long_arg(arg_string, num_args, args, value);
}

void
mlb_arg_parse(struct mlb_arg_context_t *context)
{
    int i;
    int argc;
    char **argv;
    void *callback_context;
    size_t num_args;
    struct mlb_arg_t *args;
    mlb_arg_parse_callback_t positional_callback;

    argc = context->argc;
    argv = context->argv;
    callback_context = context->callback_context;
    num_args = context->num_args;
    args = context->args;
    positional_callback = context->positional_callback;

    for (i = 1; i < argc; ++i)
    {
        const char *value;
        const char *arg_string;
        const struct mlb_arg_t *arg;

        arg_string = argv[i];
        arg = find_arg(arg_string, num_args, args, &value);

        if (arg == NULL && positional_callback != NULL)
        {
            struct mlb_arg_t positional_arg = { NULL, NULL, ARG_TYPE_POSITIONAL, NULL };

            positional_callback(callback_context, &positional_arg, argv[i]);
        } 
        else if (arg->type == ARG_TYPE_PARAMETER)
        {
            if (value == NULL)
            {
                int parameter_index;

                parameter_index = ++i;
                value = argv[parameter_index];
            }

            arg->callback(callback_context, arg, value);
        }
        else
        {
            assert(arg->type == ARG_TYPE_SWITCH);
            arg->callback(callback_context, arg, NULL);
        }
    }
}

