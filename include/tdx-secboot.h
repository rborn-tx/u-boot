// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright 2024 Toradex
 */

#ifndef __TDX_SECBOOT_H
#define __TDX_SECBOOT_H

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
