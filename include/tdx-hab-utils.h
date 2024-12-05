// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright 2024 Toradex
 */

#if (defined(CONFIG_MX6Q) || defined(CONFIG_MX6DL) || defined(CONFIG_MX6QDL))
#define IGNORE_KNOWN_HAB_EVENTS 1
#endif

#ifdef IGNORE_KNOWN_HAB_EVENTS
#define RNG_FAIL_EVENT_SIZE 36
bool is_known_fail_event(const uint8_t *data, size_t len);
#endif
