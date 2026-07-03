#include "ft_ssl.h"

#include <string.h>
#include <stdio.h>
#include <unistd.h>

#include "md5.h"
#include "sha256.h"

struct command_s {
    char *name;
    ft_ssl_status_t (*callback) (int, char **);
};

static void command_help(struct command_s *cmd_router);
static ft_ssl_status_t command_router(struct command_s *cmd_router, int argc, char **argv);

int main(int argc, char **argv) {
    struct command_s commands[] = {
        {"md5", md5_handler},
        {"sha256", sha256},
        {0}
    };

    return command_router(commands, argc, argv);
}

static ft_ssl_status_t command_router(struct command_s *cmd_router, int argc, char **argv) {
    char *help_tags[] = {"help", "-help", "--help", "-h", "--h", NULL};

    if (argc < 2) {
        goto print_help;
    }
    for (size_t i = 0; help_tags[i] != NULL; i++) {
        if (strcmp(argv[1], help_tags[i]) == 0) {
            goto print_help;
        }
    }
    while (cmd_router->name != NULL) {
        if (strcmp(cmd_router->name, argv[1]) == 0) {
            argc--;
            argv++;
            return cmd_router->callback(argc, argv);
        }
        cmd_router++;
    }
    dprintf(STDERR_FILENO, "Invalid command '%s' type \"help\" for a list.\n", argv[1]);
    return FT_SSL_ERROR;

    print_help:
        command_help(cmd_router);
        return 0;
}

static void command_help(struct command_s *cmd_router) {
    printf("Available commands:\n");
    while (cmd_router->name != NULL) {
        printf("\t%s\n", cmd_router->name);
        cmd_router++;
    }
}
