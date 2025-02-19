// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright 2024 Toradex
 */

#ifndef __TDX_SECBOOT_H
#define __TDX_SECBOOT_H

#if (defined(CONFIG_MX6Q) || defined(CONFIG_MX6DL) || defined(CONFIG_MX6QDL))
#define IGNORE_KNOWN_HAB_EVENTS 1
#endif

#ifdef IGNORE_KNOWN_HAB_EVENTS
#define RNG_FAIL_EVENT_SIZE 36
bool is_known_fail_event(const uint8_t *data, size_t len);
#endif

#ifdef CONFIG_TDX_SECBOOT_HARDENING_DBG
/* Fake HAB status for debugging purposes. */
enum dbg_hab_status_t {
	DBG_HAB_STATUS_AUTO,
	DBG_HAB_STATUS_OPEN,
	DBG_HAB_STATUS_CLOSED,
};
int tdx_secboot_set_hab_status(enum dbg_hab_status_t status);
#endif

int tdx_secboot_dev_is_open(void);

#endif	/* __TDX_SECBOOT_H */
