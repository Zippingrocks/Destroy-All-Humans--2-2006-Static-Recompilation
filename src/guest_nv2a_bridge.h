#pragma once

#include <stdint.h>

/*
 * Feed a guest D3D push-buffer kick to the host NV2A translator.  The bridge
 * is deliberately lazy: an incomplete guest device is ignored and leaves the
 * boot window untouched.
 */
void dah2_guest_gpu_commit(uint32_t guest_device, uint32_t published_put);

/* Flush translated work and present one frame on the boot window. */
void dah2_guest_gpu_present(uint32_t guest_device);

/* True when DAH2_TEST_WINDOW_HIDDEN is set. The environment is read once and
   cached: generated code calls this from inner decode loops, where a
   getenv() per iteration (a scan of the whole environment block) cost about
   a quarter of the frame thread's time during movie playback. */
int dah2_test_window_hidden(void);

/*
 * Record the push buffer's true base address (the guest_device+0 "put"
 * value observed at the earliest possible moment, right after the guest's
 * own Direct3D_CreateDevice initialization runs, before any command has
 * been appended). The bridge cannot reliably recover this later -- by the
 * time it first inspects the ring, put may have already advanced a little,
 * misaligning every packet read after it. Call once, right after device
 * creation, from the generated CreateDevice code.
 */
void dah2_guest_gpu_note_pb_base(uint32_t guest_device, uint32_t base_put);

