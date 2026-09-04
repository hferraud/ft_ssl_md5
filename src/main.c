#include "ft_ssl.h"

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#include "md5/md5.h"
#include "sha256/sha256.h"
#include "parser.h"

typedef void(*hash_str_t)(const char *, uint8_t *);
typedef ssize_t(*hash_fd_t) (int, bool, uint8_t*);

struct command_s {
    char *name;
    char *display_name;
    size_t digest_size;
    hash_str_t hash_str_function;
    hash_fd_t hash_fd_function;
};

static void command_help(struct command_s *command_table);
static ft_ssl_status_t command_router(struct command_s *command_table, int argc, char **argv);
static ft_ssl_status_t command_run(struct command_s *command, ft_ssl_options_t *options);
static ft_ssl_status_t command_run_stdin(struct command_s *command, ft_ssl_options_t *options, uint8_t *digest);
static ft_ssl_status_t command_run_strings(struct command_s *command, ft_ssl_options_t *options, uint8_t *digest);
static void print_digest(uint8_t *digest, size_t digest_size);

int main(int argc, char **argv) {
    struct command_s commands[] = {
        {"md5", "MD5", MD5_DIGEST_SIZE, NULL, NULL},
        {"sha256", "SHA256", SHA256_DIGEST_SIZE, sha256_str, sha256_fd},
        {0}
    };

    return command_router(commands, argc, argv);
}

static ft_ssl_status_t command_router(struct command_s *command_table, int argc, char **argv) {
    char *help_tags[] = {"help", "-help", "--help", "-h", "--h", NULL};
    ft_ssl_options_t options = {0};

    if (argc < 2) {
        goto print_help;
    }
    for (size_t i = 0; help_tags[i] != NULL; i++) {
        if (strcmp(argv[1], help_tags[i]) == 0) {
            goto print_help;
        }
    }
    while (command_table->name != NULL) {
        if (strcmp(command_table->name, argv[1]) == 0) {
            argc--;
            argv++;
            ft_ssl_parser(argc, argv, &options);
            return command_run(command_table, &options);
        }
        command_table++;
    }
    dprintf(STDERR_FILENO, "Invalid command '%s' type \"help\" for a list.\n", argv[1]);
    return FT_SSL_ERROR;

    print_help:
        command_help(command_table);
        return 0;
}

static ft_ssl_status_t command_run(struct command_s *command, ft_ssl_options_t *options)
{
    uint8_t *digest;

    digest = malloc(command->digest_size);
    if (digest == NULL)
    {
        return FT_SSL_ERROR;
    }
    command_run_stdin(command, options, digest);
    command_run_strings(command, options, digest);
    free(digest);
    return FT_SSL_OK;
}

static ft_ssl_status_t command_run_stdin(struct command_s *command, ft_ssl_options_t *options, uint8_t *digest)
{
    if (options->quiet)
    {
        if (sha256_fd(STDIN_FILENO, false, digest) >= 0)
        {
            print_digest(digest, command->digest_size);
        }

    } else if (options->print_back)
    {
        if (sha256_fd(STDIN_FILENO, true, digest) >= 0)
        {
            return FT_SSL_ERROR;
        }
        print_digest(digest, command->digest_size);
    } else
    {
        printf("(stdin) = ");
        if (sha256_fd(STDIN_FILENO, false, digest) != FT_SSL_OK)
        {
            return FT_SSL_ERROR;
        }
    }
    return FT_SSL_OK;
}

// static ft_ssl_status_t command_run_file(struct command_s *command, ft_ssl_options_t *options)
// {
//     uint8_t *buffer;
//
//
// }

static ft_ssl_status_t command_run_strings(struct command_s *command, ft_ssl_options_t *options, uint8_t *digest)
{
    for (size_t i = 0; i < options->string_count; i++)
    {
        command->hash_str_function(options->strings[i], digest);
        if (options->quiet)
        {
            print_digest(digest, command->digest_size);
        }
        else if (options->reverse)
        {
            print_digest(digest, command->digest_size);
            printf(" \"%s\"\n", options->strings[i]);
        }
        else
        {
            printf("%s (\"%s\") = ", command->display_name, options->strings[i]);
            print_digest(digest, command->digest_size);
            printf("\n");
        }
    }
    return FT_SSL_OK;
}

static void command_help(struct command_s *command_table)
{
    printf("Available commands:\n");
    while (command_table->name != NULL) {
        printf("\t%s\n", command_table->name);
        command_table++;
    }
}

static void print_digest(uint8_t *digest, size_t digest_size)
{
    for (size_t i = 0; i < digest_size; i++)
    {
        printf("%02x", digest[i]);
    }
}
