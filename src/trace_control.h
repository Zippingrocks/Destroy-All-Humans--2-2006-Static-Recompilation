#ifndef DAH2_TRACE_CONTROL_H
#define DAH2_TRACE_CONTROL_H

#include <stdio.h>

extern int g_dah2_verbose_trace;

void dah2_trace_initialize(void);

#define DAH2_TRACE_FPRINTF(stream, ...) \
    (g_dah2_verbose_trace ? fprintf((stream), __VA_ARGS__) : 0)

#endif /* DAH2_TRACE_CONTROL_H */