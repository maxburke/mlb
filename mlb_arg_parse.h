/*
 * arg_parse.h / 2013 Max Burke / Public Domain
 */

#ifndef ARG_PARSE_H
#define ARG_PARSE_H

enum mlb_arg_type_t
{
    /*
     * Switches have no other data to be parsed, they usually represent
     * boolean options, like whether or not to display a help message,
     * or a verbosity flag. 
     * For example, 
     *   foo.exe --verbose
     */
    ARG_TYPE_SWITCH,

    /*
     * Parameters are separated from the argument by whitespace and require
     * a value to be passed right after. Short arguments require that the
     * parameter abut the short argument, long arguments may have the 
     * argument separated by a space or equals sign. 
     * For example,
     *   foo.exe --context 2
     *   foo.exe --context=2
     *   foo.exe -C2
     *
     * Currently no error checking is done on the parameters, so if the user 
     * uses them incorrectly by, say, omitting the parameter (foo.exe --context -v)
     * no error is raised.
     */
    ARG_TYPE_PARAMETER,

    /*
     * Positional arguments are everything after the last named argument. For
     * example, these may be the list of files to compile with a compiler.
     * For example, 
     *   foo.exe --verbose bar.c baz.c
     */
    ARG_TYPE_POSITIONAL
};

struct mlb_arg_t;

typedef void (*mlb_arg_parse_callback_t)(void *context, const struct mlb_arg_t *arg, const char *value);

struct mlb_arg_t
{
    const char *short_form;
    const char *long_form;
    enum mlb_arg_type_t type;
    mlb_arg_parse_callback_t callback;
};

struct mlb_arg_context_t
{
    int argc;
    char **argv;
    void *callback_context;
    size_t num_args;
    struct mlb_arg_t *args;
    mlb_arg_parse_callback_t positional_callback;
};

void
mlb_arg_parse(struct mlb_arg_context_t *context);

#endif

