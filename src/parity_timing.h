#ifndef DAH2_PARITY_TIMING_H
#define DAH2_PARITY_TIMING_H
#include <stdint.h>
/* Shared implementation provides one ordinal/budget across generated TUs.
 * Reads guest state only; diagnostic host timestamps are not guest timing. */
void dah2_parity_timing(const char *kind, uint32_t address, uint32_t frame_pointer);
#endif
