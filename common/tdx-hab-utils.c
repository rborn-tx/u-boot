// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright 2024 Toradex
 */

#include <common.h>
#include <tdx-hab-utils.h>

#ifdef IGNORE_KNOWN_HAB_EVENTS
static uint8_t known_rng_fail_event[][RNG_FAIL_EVENT_SIZE] = {
        { 0xdb, 0x00, 0x24, 0x42,  0x69, 0x30, 0xe1, 0x1d,
          0x00, 0x04, 0x00, 0x02,  0x40, 0x00, 0x36, 0x06,
          0x55, 0x55, 0x00, 0x03,  0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x01 },
};

bool is_known_fail_event(const uint8_t *data, size_t len)
{
        int i;

        for (i = 0; i < ARRAY_SIZE(known_rng_fail_event); i++) {
                if (memcmp(data, known_rng_fail_event[i],
                           min_t(size_t, len, RNG_FAIL_EVENT_SIZE)) == 0) {
                        return true;
                }
        }

        return false;
}
#endif
