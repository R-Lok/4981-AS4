#ifndef ARGS_H
#define ARGS_H
#include <netinet/in.h>

int parse_port(int argc, char **argv, in_port_t *port_var);

#endif
