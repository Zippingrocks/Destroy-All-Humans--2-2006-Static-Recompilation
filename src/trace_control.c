#include "trace_control.h"

#include <stdlib.h>

int g_dah2_verbose_trace;

void dah2_trace_initialize(void)
{
    g_dah2_verbose_trace = getenv("DAH2_VERBOSE_TRACE") != NULL &&
                           getenv("DAH2_QUIET_TRACE") == NULL;
}