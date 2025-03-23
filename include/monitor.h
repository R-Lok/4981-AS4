#ifndef MONITOR_H
#define MONITOR_H
#include <signal.h>

int start_monitor(int child_end, const volatile sig_atomic_t *running);

#endif
