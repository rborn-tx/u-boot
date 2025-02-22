// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright 2024 Toradex
 */

#include <common.h>
#include <command.h>
#include <tdx-secboot.h>

#if defined(CONFIG_IMX_HAB)
#include <asm/mach-imx/hab.h>
#elif defined(CONFIG_AHAB_BOOT)
#include <firmware/imx/sci/sci.h>
#endif

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

#ifdef CONFIG_TDX_SECBOOT_HARDENING_DBG
/* Fake HAB status for debugging purposes. */
static enum dbg_hab_status_t dbg_hab_status = DBG_HAB_STATUS_AUTO;

int tdx_secboot_set_hab_status(enum dbg_hab_status_t status)
{
	switch (status) {
	case DBG_HAB_STATUS_AUTO:
	case DBG_HAB_STATUS_OPEN:
	case DBG_HAB_STATUS_CLOSED:
		dbg_hab_status = status;
		break;
	default:
		return 1;
	}

	return 0;
}
#endif

static int _tdx_secboot_dev_is_open(void)
{
#if defined(CONFIG_IMX_HAB)
	if (imx_hab_is_enabled()) {
		/* Device is closed (OR some error occurred). */
		/* Notice that imx_hab_is_enabled() returns bool as per its
		 * prototype but checking its code it can return a negative
		 * value in case of fuse read errors. */
		/* TODO: Evaluate if this is the best we can do here. */
		return 0;
	}
#elif defined(CONFIG_AHAB_BOOT)
	u16 lc;
	if (sc_seco_chip_info(-1, &lc, NULL, NULL, NULL)) {
		/* Some error occurred. */
		return 0;
	}
	switch (lc) {
	case 0x1:	/* Pristine */
	case 0x2:	/* Fab */
	case 0x8:	/* Open */
		debug("Device is in a pre NXP-closed state!\n");
		break;
	case 0x20:	/* NXP closed */
		debug("Device is in a NXP-closed state!\n");
		break;
	case 0x80:	/* OEM closed */
		debug("Device is in OEM-closed state!\n");
		return 0;
	case 0x100:	/* Partial field return */
	case 0x200:	/* Full field return */
	case 0x400:	/* No return */
		debug("Device is in some 'return' state!\n");
		return 1;
	default:	/* Unknown */
		break;
	}
#else
#error Neither CONFIG_IMX_HAB nor CONFIG_AHAB_BOOT is set
#endif

	/* Device is (assumed to be) open. */
	return 1;
}

/**
 * tdx_secboot_dev_is_open - Determine if device is open (w.r.t. HAB/AHAB)
 * Return: 1 if device is open or 0 otherwise.
 *
 * Determine if device is open for the purpose of the Toradex secure boot
 * solution.
 */
int tdx_secboot_dev_is_open(void)
{
	int dev_open = _tdx_secboot_dev_is_open();

#ifdef CONFIG_TDX_SECBOOT_HARDENING_DBG
	/* Override results (for debugging). */
	if (dbg_hab_status == DBG_HAB_STATUS_OPEN) {
		dev_open = 1;
	} else if (dbg_hab_status == DBG_HAB_STATUS_CLOSED) {
		dev_open = 0;
	}
#endif
	return dev_open;
}

/* Returns 0 if device is closed, 1 if it is open or on error.
 */
static int do_tdx_is_closed(struct cmd_tbl *cmdtp, int flag, int argc,
			    char *const argv[])
{
	int retval;

	if (argc != 1) {
		cmd_usage(cmdtp);
		return 1;
	}

	retval = _tdx_secboot_dev_is_open();

	if (retval) {
		printf("Device is open.\n");
	} else {
		printf("Device is closed.\n");
	}

	return retval;
}

U_BOOT_CMD(tdx_is_closed, CONFIG_SYS_MAXARGS, 1, do_tdx_is_closed,
	   "Checks whether device has been closed for HAB/AHAB","");
