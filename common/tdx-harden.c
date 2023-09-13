// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright 2023 Toradex
 */

#include <common.h>
#include <compiler.h>
#include <command.h>
#include <console.h>
#include <log.h>
#include <fdt_support.h>
#include <asm/global_data.h>
#include <tdx-harden.h>

#if defined(CONFIG_IMX_HAB)
#include <asm/mach-imx/hab.h>
#elif defined(CONFIG_AHAB_BOOT)
#include <asm/arch/sci/sci.h>
#endif

DECLARE_GLOBAL_DATA_PTR;

/* Path of node in FDT containing all Secure Boot setup. */
static const char secboot_node_path[] = TDX_SECBOOT_NODE_PATH;

#ifdef CONFIG_TDX_SECBOOT_HARDENING_DBG
/* Fake HAB status for debugging purposes. */
enum dbg_hab_status_t {
	DBG_HAB_STATUS_AUTO,
	DBG_HAB_STATUS_OPEN,
	DBG_HAB_STATUS_CLOSED,
};

/* Fake hardening status for debugging purposes. */
enum dbg_hdn_status_t {
	DBG_HDN_STATUS_AUTO,
	DBG_HDN_STATUS_DISABLED,
	DBG_HDN_STATUS_ENABLED,
};

enum dbg_hab_status_t dbg_hab_status = DBG_HAB_STATUS_AUTO;
enum dbg_hdn_status_t dbg_hdn_status = DBG_HDN_STATUS_AUTO;
#endif

static int _tdx_hardening_enabled(void)
{
	const void *dis_prop;
	int secboot_offset, prop_len;

	if (!gd->fdt_blob) {
		debug("No FDT blob -> hardening disabled\n");
		return 0;
	}

	secboot_offset = fdt_path_offset(gd->fdt_blob, secboot_node_path);
	if (secboot_offset < 0) {
		debug("Node '%s' does not exist -> hardening disabled\n",
		      secboot_node_path);
		return 0;
	}

	dis_prop = fdt_getprop(gd->fdt_blob,
			       secboot_offset, "disabled", &prop_len);
	if (dis_prop) {
		debug("Hardening explicitly disabled by property (len=%d)\n",
		      prop_len);
		return 0;
	}

	debug("Hardening is enabled\n");
	return 1;
}

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
 * tdx_hardening_enabled - Determine if Toradex U-Boot hardening is enabled
 * Return: 1 if hardening is enabled or 0 otherwise.
 *
 * Check FDT to see if the hardening feature is enabled. Currently the feature
 * is enabled if the node defined by `secboot_node_path` exists in the FDT and
 * the same node does not have a "disabled" property under it.
 */
int tdx_hardening_enabled(void)
{
	int hdn_enabled = _tdx_hardening_enabled();

#ifdef CONFIG_TDX_SECBOOT_HARDENING_DBG
	/* Override results (for debugging). */
	if (dbg_hdn_status == DBG_HDN_STATUS_ENABLED) {
		hdn_enabled = 1;
	} else if (dbg_hdn_status == DBG_HDN_STATUS_DISABLED) {
		hdn_enabled = 0;
	}
#endif
	return hdn_enabled;
}

/**
 * tdx_secboot_dev_is_open - Determine if device is open (w.r.t. HAB/AHAB)
 * Return: 1 if device is open or 0 otherwise.
 *
 * Determine if device is open for the purpose of the Toradex U-Boot
 * hardening.
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

#ifdef CONFIG_TDX_CLI_PROTECTION
/**
 * tdx_cli_access_enabled - Determine if U-Boot CLI access is to be enabled
 * Return: 1 if CLI access is to be enabled or 0 otherwise.
 */
int tdx_cli_access_enabled(void)
{
	const void *en_prop;
	int secboot_offset, prop_len;

	if (!tdx_hardening_enabled())
		return 1;
	if (tdx_secboot_dev_is_open())
		return 1;
	if (!gd->fdt_blob)
		return 1;	/* no hardening */

	secboot_offset = fdt_path_offset(gd->fdt_blob, secboot_node_path);
	if (secboot_offset < 0)
		return 1;	/* no hardening */

	/* Hardening is enabled and device is closed: CLI access should be
	   disabled unless the control DTB says otherwise: check it.  */
	en_prop = fdt_getprop(gd->fdt_blob, secboot_offset,
			       "enable-cli-when-closed", &prop_len);
	if (en_prop) {
		debug("U-Boot CLI access enabled by property (len=%d)\n",
		      prop_len);
		return 1;
	}

	debug("U-Boot CLI access disabled\n");
	return 0;
}

void tdx_secure_boot_cmd(const char *cmd)
{
	int rc;

	printf("## U-Boot CLI access is disabled due to Secure Boot\n");

	disable_ctrlc(1);
	rc = run_command_list(cmd, -1, 0);

	panic("## ERROR: \"%s\" returned (code %d) and CLI access is "
	      "disabled\n", cmd, rc);
}
#endif

static int hardening_info(void)
{
	int hdn_enabled = tdx_hardening_enabled();
	int dev_open = tdx_secboot_dev_is_open();

	printf("Hardening : %s\n", hdn_enabled ? "enabled" : "disabled");
	printf("HAB status: %s\n", dev_open ? "open" : "closed");

	return CMD_RET_SUCCESS;
}

#ifdef CONFIG_TDX_SECBOOT_HARDENING_DBG
static int hardening_set_hab_status(int argc, char *const argv[])
{
	const char *str_subcmd;

	if (argc < 1)
		return CMD_RET_USAGE;

	str_subcmd = argv[0];
	if (!strcmp(str_subcmd, "auto")) {
		dbg_hab_status = DBG_HAB_STATUS_AUTO;
	} else if (!strcmp(str_subcmd, "open")) {
		dbg_hab_status = DBG_HAB_STATUS_OPEN;
	} else if (!strcmp(str_subcmd, "closed")) {
		dbg_hab_status = DBG_HAB_STATUS_CLOSED;
	} else {
		return CMD_RET_USAGE;
	}

	return CMD_RET_SUCCESS;
}

static int hardening_set_hdn_status(int argc, char *const argv[])
{
	const char *str_subcmd;

	if (argc < 1)
		return CMD_RET_USAGE;

	str_subcmd = argv[0];
	if (!strcmp(str_subcmd, "auto")) {
		dbg_hdn_status = DBG_HDN_STATUS_AUTO;
	} else if (!strcmp(str_subcmd, "enabled")) {
		dbg_hdn_status = DBG_HDN_STATUS_ENABLED;
	} else if (!strcmp(str_subcmd, "disabled")) {
		dbg_hdn_status = DBG_HDN_STATUS_DISABLED;
	} else {
		return CMD_RET_USAGE;
	}

	return CMD_RET_SUCCESS;
}
#endif

static int do_hardening(struct cmd_tbl *cmdtp, int flag, int argc,
			char *const argv[])
{
	const char *str_cmd;

	if (argc < 2)
		return CMD_RET_USAGE;
	str_cmd = argv[1];
	argc -= 2;
	argv += 2;

	if (!strcmp(str_cmd, "info")) {
		return hardening_info();
#ifdef CONFIG_TDX_SECBOOT_HARDENING_DBG
	} else if (!strcmp(str_cmd, "set-hab-status")) {
		return hardening_set_hab_status(argc, argv);
	} else if (!strcmp(str_cmd, "set-hdn-status")) {
		return hardening_set_hdn_status(argc, argv);
#endif
	}

	return CMD_RET_USAGE;

}

U_BOOT_CMD(hardening, 5, 0, do_hardening,
	   "hardening status and control",
	   "info - show hardening feature information\n"
#ifdef CONFIG_TDX_SECBOOT_HARDENING_DBG
	   "hardening set-hab-status <auto|open|closed>"
	   " - fake HAB status for testing purposes\n"
	   "hardening set-hdn-status <auto|enabled|disabled>"
	   " - fake hardening status for testing purposes\n"
#endif
	  );

#ifndef CONFIG_LMB
/* We assume CONFIG_LMB is set so that the load commands have protections to
 * prevent overwriting the reserved memory areas; if CONFIG_LMB is not set then
 * either this configuration option was replaced by something else or the
 * U-Boot configuration is wrong. */
#error Toradex hardening assumes CONFIG_LMB is set
#endif

#ifdef CONFIG_UPDATE_TFTP
/* Self-updates are likely not safe. */
#error Toradex hardening assumes CONFIG_UPDATE_TFTP is not set
#endif
