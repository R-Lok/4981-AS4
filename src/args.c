#include <../include/args.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static int convert_port(const char *str, in_port_t *port);
void       print_usage(void);

int parse_port(int argc, char **argv, in_port_t *port_var)
{
    int opt;

    while((opt = getopt(argc, argv, ":p:")) != -1)
    {
        switch(opt)
        {
            case 'p':
                if(convert_port(optarg, port_var) != 0)
                {
                    fprintf(stderr, "Port must be between 0 to 65535\n");
                    return 1;    // port not valid
                }
                break;
            case ':':
                fprintf(stderr, "Missing argument for flag -p\n");
                print_usage();
                exit(EXIT_FAILURE);
            default:
                fprintf(stderr, "Unrecognized flag entered: %c. Terminating.\n", optopt);
                print_usage();
                return 1;
        }
    }
    return 0;
}

static int convert_port(const char *str, in_port_t *port)
{
    char *endptr;
    long  val;

    val = strtol(str, &endptr, 10);    // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)

    if(endptr == str)
    {
        return 1;    // failure, no number extracted
    }

    if(val < 0 || val > UINT16_MAX)
    {
        return 1;    // failure, port number not valid
    }

    if(*endptr != '\0')
    {
        return 1;    // failure, port argument contains invalid trailing chars
    }

    *port = (in_port_t)val;
    return 0;
}

void print_usage(void)
{
    printf("To run: ./main \n Optional flags: -p <port number between 0 and 65525>");
}
