#ifndef ARGS_H
#define ARGS_H
#include <netinet/in.h>

int parse_args(int argc, char **argv, in_port_t *port_var, int *max_workers);

#endif
