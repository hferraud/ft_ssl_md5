#include "md5.h"

#include <stdio.h>
#include <string.h>

#include "parser.h"
#include "crypto.h"

ft_ssl_status_t md5_handler(int argc, char **argv) {
    md5_options_t options = {0};

    md5_parser(argc, argv, &options);
    printf("p=%d\n", options.print_back);
    printf("q=%d\n", options.quiet);
    printf("r=%d\n", options.reverse);
    printf("s=%s\n", options.sum_input);
    if (options.sum_input != NULL) {
        md5((uint8_t*)options.sum_input, strlen(options.sum_input));
    }
    return FT_SSL_OK;
}
