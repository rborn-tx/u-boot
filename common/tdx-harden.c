// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright 2023 Toradex
 */

/* To see messages, also set CONFIG_LOG_MAX_LEVEL=8 and CONFIG_LOG_LEVEL=8. */
/* #define DEBUG */
/* #define LOG_DEBUG */

#include <common.h>
#include <compiler.h>
#include <command.h>
#include <console.h>
#include <log.h>
#include <fdt_support.h>
#include <linux/ctype.h>
#include <linux/string.h>
#include <asm/global_data.h>
#include <tdx-secboot.h>
#include <tdx-harden.h>

DECLARE_GLOBAL_DATA_PTR;

/* Path of node in FDT containing all Secure Boot setup. */
static const char secboot_node_path[] = TDX_SECBOOT_NODE_PATH;

#ifdef CONFIG_TDX_SECBOOT_HARDENING_DBG
/* Fake hardening status for debugging purposes. */
enum dbg_hdn_status_t {
	DBG_HDN_STATUS_AUTO,
	DBG_HDN_STATUS_DISABLED,
	DBG_HDN_STATUS_ENABLED,
};

static enum dbg_hdn_status_t dbg_hdn_status = DBG_HDN_STATUS_AUTO;
#endif

#ifdef CONFIG_TDX_BOOTARGS_PROTECTION
/* Path of node in OS FDT containing all bootargs properties. */
static const char bootargs_node_path[] = TDX_BOOTARGS_NODE_PATH;

enum bootarg_param_type_t {
	BPARAM_NONE,
	BPARAM_INTEGER,
	BPARAM_OSTREE_PATH,
	BPARAM_GENERIC_UUID,
};

struct bootarg_spec_t {
	const char *param;
	enum bootarg_param_type_t type;
	const char *conflict;
};

static const struct bootarg_spec_t bootarg_spec[] = {
	{ "ostree=", BPARAM_OSTREE_PATH, NULL },
	{ "root=PARTUUID=", BPARAM_GENERIC_UUID, "root=" }
#if 0
	/* Examples */
	{ "loglevel=", BPARAM_INTEGER, NULL },
	{ "nowb", BPARAM_NONE, NULL },
#endif
};

#define BOOTARG_SPEC_LEN (sizeof(bootarg_spec) / sizeof(bootarg_spec[0]))
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

#ifdef CONFIG_TDX_BOOTARGS_PROTECTION
/**
 * _tdx_valid_var_bootarg - Check single argument in bootargs
 *
 * TODO: Add support for quoted strings.
 */
static int _tdx_valid_var_bootarg(const char *value,
				  enum bootarg_param_type_t type,
				  const char **eptr)
{
	const char *valp = value;

	debug("check value '%.10s...' against type=%d\n", value, (int) type);

	switch (type) {
	case BPARAM_NONE:
		break;
	case BPARAM_INTEGER: {
		while (isdigit(*valp))
			valp++;
		if (valp == value)
			return 0;
		break;
	}
	case BPARAM_OSTREE_PATH: {
		/* Accept only a limited set of characters. */
		while (isalnum(*valp) || *valp == '/' || *valp == '.')
			valp++;
		if (valp == value)
			return 0;
		break;
	}
	case BPARAM_GENERIC_UUID: {
		/* Accept hex digits and dashes. */
		while (isxdigit(*valp) || *valp == '-')
			valp++;
		if (valp == value)
			return 0;
		break;
	}
	default:
		printf("Unhandled bootarg param type %d\n", (int) type);
		return 0;
	}

	/* Ensure argument is finished by space or NUL. */
	if (*valp == '\0' || isspace(*valp)) {
		if (eptr)
			*eptr = valp;
		return 1;
	}

	return 0;
}

/**
 * _tdx_valid_var_bootargs - Check the variable part of bootargs
 */
static int _tdx_valid_var_bootargs(const char *bootargs, const char *reqargs)
{
	const char *args = bootargs, *value = NULL, *eptr;

	while (*args) {
		int bi;
		for (bi = 0; bi < BOOTARG_SPEC_LEN; bi++) {
			int plen = strlen(bootarg_spec[bi].param);
			if (!strncmp(args, bootarg_spec[bi].param, plen)) {
				debug("arg '%s'\n", bootarg_spec[bi].param);
				value = &args[plen];
				break;
			}
		}
		if (bi >= BOOTARG_SPEC_LEN) {
			eprintf("## Unexpected argument in variable bootargs: "
				"%.16s...\n", args);
			return 0;
		}

		if (!_tdx_valid_var_bootarg(value, bootarg_spec[bi].type, &eptr)) {
			eprintf("## Argument validation failed for bootarg "
				"%.16s...\n", args);
			return 0;
		}

		/* Check if the parameter specified in the variable part conflicts
                   with a parameter in the required (fixed) part; this prevents
                   parameters to be overriden in the variable part when they are
                   supposed to be present only in the fixed part of the bootargs. */
		if (bootarg_spec[bi].conflict) {
			const char *reqptr = strstr(reqargs, bootarg_spec[bi].conflict);
			int conflict = 0;
			if (reqptr && reqptr == reqargs) {
				/* found at the beginning of the reqargs. */
				conflict = 1;

			} else if (reqptr && reqptr != reqargs) {
				/* found not at the beginning: confirm. */
				reqptr--;
				if (isspace(*reqptr)) conflict = 1;
			}
			if (conflict) {
				eprintf("## Conflicting argument in variable bootargs: "
					"%.16s...\n", args);
				return 0;
			}
		}

		args = eptr;
		args = skip_spaces(args);
	}

	return 1;
}

/**
 * tdx_valid_bootargs - Check if bootargs string is valid
 * Return: 1 if valid or 0 otherwise.
 *
 * Check bootargs string against information in FDT (the one passed to the OS);
 * the FDT is expected to contain a copy of the initial part of the kernel
 * command line (specifically the part that can be determined at build-time).
 */
int tdx_valid_bootargs(void *fdt, const char *bootargs)
{
	static const char req_prop[] = "required-bootargs";
	const char *req_args = NULL;
	const char *args = bootargs;
	int req_len = 0;
	int node_offset;

	node_offset = fdt_path_offset(fdt, bootargs_node_path);
	if (node_offset < 0) {
		eprintf("## WARNING: Required node \"%s\" could not be found "
			"in device-tree.\n", bootargs_node_path);
		return 0;
	}

	req_args = fdt_getprop(fdt, node_offset, req_prop, &req_len);
	if (!req_args) {
		eprintf("## WARNING: Required property \"%s/%s\" could not be "
			"found in device-tree.\n", bootargs_node_path, req_prop);
		return 0;
	}

	debug("** bootargs(env)=\"%s\"\n", bootargs);
	debug("** bootargs(fdt)=\"%.*s\" [L=%d]\n", req_len, req_args, req_len);

	/* Strings should be NUL-terminated but let us be careful. */
	req_len = strnlen(req_args, req_len);

	/* First part of bootargs must match required property in FDT. */
	if (req_len) {
		args = skip_spaces(args);
		debug("check 1st part:\n A: \"%.*s\"\n B: \"%.*s\"\n",
		      req_len, args, req_len, req_args);
		if (strncmp(args, req_args, req_len)) {
			debug("req_args comparison failed\n");
			goto fixpart_invalid;
		}
		args += req_len;
	}

	/* Second part (if any) is variable. */
	if (*args) {
		if (req_len && !isspace(*args)) {
			debug("no space before variable args\n");
			goto fixpart_invalid;
		}
		args = skip_spaces(args);
	}

	debug("variable part to validate: \"%s\"\n", args);
	if (!_tdx_valid_var_bootargs(args, req_args))
		goto varpart_invalid;

	return 1;

fixpart_invalid:
	eprintf("## WARNING: Initial part of passed bootargs string (A) does "
		"not match '%s' property (B) in device-tree.\n", req_prop);
	eprintf("##  A: \"%s\"\n", skip_spaces(bootargs));
	eprintf("##  B: \"%.*s\"\n", req_len, req_args);
	return 0;

varpart_invalid:
	eprintf("## WARNING: Validation of the variable part of bootargs "
		"failed; the full bootargs string (A) and its fixed part "
		"(as defined in the '%s' property inside the device-tree) "
		"follow:\n", req_prop);
	eprintf("##  A: \"%s\"\n", skip_spaces(bootargs));
	eprintf("##  B: \"%.*s\"\n", req_len, req_args);
	return 0;
}
#endif

static int show_hardening_info(void)
{
	int hdn_enabled = tdx_hardening_enabled();
	int dev_open = tdx_secboot_dev_is_open();

	printf("Hardening : %s\n", hdn_enabled ? "enabled" : "disabled");
	printf("HAB status: %s\n", dev_open ? "open" : "closed");

	return CMD_RET_SUCCESS;
}

#ifdef CONFIG_TDX_SECBOOT_HARDENING_DBG
static int set_hab_status(int argc, char *const argv[])
{
	const char *str_subcmd;
	enum dbg_hab_status_t status = DBG_HAB_STATUS_AUTO;

	if (argc < 1)
		return CMD_RET_USAGE;

	str_subcmd = argv[0];
	if (!strcmp(str_subcmd, "auto")) {
		status = DBG_HAB_STATUS_AUTO;
	} else if (!strcmp(str_subcmd, "open")) {
		status = DBG_HAB_STATUS_OPEN;
	} else if (!strcmp(str_subcmd, "closed")) {
		status = DBG_HAB_STATUS_CLOSED;
	} else {
		return CMD_RET_USAGE;
	}

	if (tdx_secboot_set_hab_status(status))
		return CMD_RET_FAILURE;

	return CMD_RET_SUCCESS;
}

static int set_hardening_status(int argc, char *const argv[])
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
		return show_hardening_info();
#ifdef CONFIG_TDX_SECBOOT_HARDENING_DBG
	} else if (!strcmp(str_cmd, "set-hab-status")) {
		return set_hab_status(argc, argv);
	} else if (!strcmp(str_cmd, "set-hdn-status")) {
		return set_hardening_status(argc, argv);
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
