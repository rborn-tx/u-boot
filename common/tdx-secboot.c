// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright 2024 Toradex
 */

#include <common.h>
#include <command.h>
#include <env.h>
#include <malloc.h>
#include <tdx-secboot.h>
#include <tdx-harden.h>

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
#warning Neither CONFIG_IMX_HAB nor CONFIG_AHAB_BOOT is set
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

typedef enum {
	PROP_VAL_FALSE,
	PROP_VAL_TRUE,
	PROP_VAL_DYN = 0xff
} secboot_prop_value_t;

#define MAX_FLAG_NAME 5

struct secboot_prop {
	const char *name;  /* Full name. */
	const char  flag[MAX_FLAG_NAME];  /* Short name (flag). */
#if 0
	const char *desc;  /* Description (not used atm). */
#endif
	secboot_prop_value_t value;  /* Static value. */
};

#define SECBOOT_PROP(_name, _flag, _desc, _value) \
	{ _name, _flag, _value }

static const struct secboot_prop secboot_props[] = {
	SECBOOT_PROP("dev.closed", "clo", "device is closed",
		     PROP_VAL_DYN),
	SECBOOT_PROP("dev.closed-raw", "clor", "device is closed (low-level)",
		     PROP_VAL_DYN),
	SECBOOT_PROP("hdn.enabled", "hdn", "hardening enabled at runtime",
		     PROP_VAL_DYN),
	SECBOOT_PROP("bld.secboot", "sec", "built with secboot ((A)HAB/K3)",
		     (CONFIG_IS_ENABLED(IMX_HAB) ||
		      CONFIG_IS_ENABLED(AHAB_BOOT) ||
		      CONFIG_IS_ENABLED(ARCH_K3)) ?
		     PROP_VAL_TRUE : PROP_VAL_FALSE),
	SECBOOT_PROP("bld.hdn.all", "bhdn", "built with all hardening enabled",
		     (CONFIG_IS_ENABLED(TDX_SECBOOT_HARDENING) &&
		      CONFIG_IS_ENABLED(TDX_CMD_WHITELIST) &&
		      CONFIG_IS_ENABLED(TDX_BOOTM_PROTECTION) &&
		      CONFIG_IS_ENABLED(TDX_CLI_PROTECTION) &&
		      CONFIG_IS_ENABLED(TDX_BOOTARGS_PROTECTION)) ?
		     PROP_VAL_TRUE : PROP_VAL_FALSE),
	SECBOOT_PROP("bld.hdn.dbg", "bhdb", "built with hardening debug",
		     (CONFIG_IS_ENABLED(TDX_SECBOOT_HARDENING) &&
		      CONFIG_IS_ENABLED(TDX_SECBOOT_HARDENING_DBG)) ?
		     PROP_VAL_TRUE : PROP_VAL_FALSE),
	SECBOOT_PROP("bld.hdn.whitelist", "bwl", "built with whitelist feature",
		     CONFIG_IS_ENABLED(TDX_CMD_WHITELIST) ?
		     PROP_VAL_TRUE : PROP_VAL_FALSE),
	SECBOOT_PROP("bld.hdn.bootm", "bbmp", "built with bootm protection",
		     CONFIG_IS_ENABLED(TDX_BOOTM_PROTECTION) ?
		     PROP_VAL_TRUE : PROP_VAL_FALSE),
	SECBOOT_PROP("bld.hdn.cli", "bclp", "built with cli protection",
		     CONFIG_IS_ENABLED(TDX_CLI_PROTECTION) ?
		     PROP_VAL_TRUE : PROP_VAL_FALSE),
	SECBOOT_PROP("bld.hdn.bootargs", "bbap", "built with bootargs protection",
		     CONFIG_IS_ENABLED(TDX_BOOTARGS_PROTECTION) ?
		     PROP_VAL_TRUE : PROP_VAL_FALSE),
};

#define SECBOOT_PROPS_LEN (sizeof(secboot_props) / sizeof(secboot_props[0]))

static int _secboot_get_prop(const char *prop, int *val)
{
	int index;
	for (index=0; index < SECBOOT_PROPS_LEN; index++) {
		if (strcmp(prop, secboot_props[index].name))
			continue;
		/* Handle dynamic values. */
		if (secboot_props[index].value == PROP_VAL_DYN) {
			if (!strcmp(prop, "dev.closed")) {
				*val = !tdx_secboot_dev_is_open();
			} else if (!strcmp(prop, "dev.closed-raw")) {
				*val = !_tdx_secboot_dev_is_open();
			} else if (!strcmp(prop, "hdn.enabled")) {
				*val = tdx_hardening_enabled();
			} else {
				return 1;
			}
			return 0;
		}
		/* Handle static values. */
		*val = secboot_props[index].value;
		return 0;
	}

	*val = 0xff;
	return 1; /* not found */
}

static int do_secboot_get(struct cmd_tbl *cmdtp, int flag, int argc,
			  char *const argv[])
{
	const char *prop = NULL;
	const char *name = NULL;

	if (argc <= 1) {
		/* No parameters: success; this can be used to check the */
		/* existence of the command. */
		return CMD_RET_SUCCESS;
	} else if (argc > 3) {
		return CMD_RET_USAGE;
	}

	prop = cmd_arg1(argc, argv);
	name = cmd_arg2(argc, argv);

	if (prop && !name && !strcmp(prop, "list")) {
		int index;
		printf("Available properties (flags):\n");
		for (index=0; index < SECBOOT_PROPS_LEN; index++) {
			int ret, val;
			ret = _secboot_get_prop(
				secboot_props[index].name, &val);
			printf("- %s (%s): %s\n",
			       secboot_props[index].name,
			       secboot_props[index].flag,
			       ret == 0 ? (val ? "1" : "0") : "unknown");
		}
		return CMD_RET_SUCCESS;
	}

	if (prop && !strcmp(prop, "flags")) {
		int index;
		char *ptr;
		char *buf = calloc(sizeof(char),
				   SECBOOT_PROPS_LEN * (MAX_FLAG_NAME + 2) + 1);
		if (!buf)
			return CMD_RET_FAILURE;
		ptr = buf;
		for (index=0; index < SECBOOT_PROPS_LEN; index++) {
			int ret, val;
			ret = _secboot_get_prop(
				secboot_props[index].name, &val);
			/* separator */
			if (index)
				*ptr++ = ' ';
			/* append a +/-/? to indicate true/false/unknown */
			sprintf(ptr, "%s%c",
				secboot_props[index].flag,
				ret == 0 ? (val ? '+' : '-') : '?');
			ptr += strlen(ptr);
		}
		if (name) {
			env_set(name, buf);
		} else {
			printf("%s\n", buf);
		}
		free(buf);
		return CMD_RET_SUCCESS;
	}

	if (prop) {
		int ret, val;
		/* Return an exit code of 16 to indicate an unknown property. */
		if (_secboot_get_prop(prop, &val) != 0) {
			eprintf("Unknown property: %s\n", prop);
			return 16;
		}
		if (name) {
			env_set_ulong(name, (ulong) val);
		} else {
			printf("%s: %d\n", prop, val);
		}
		return CMD_RET_SUCCESS;
	}

	return CMD_RET_USAGE;
}
 
U_BOOT_CMD(
	tdx_secboot_get, 5, 0, do_secboot_get,
	"show/read boolean property relating to secure boot",
	"list\n"
	"    - list available properties\n"
	"\n"
	"tdx_secboot_get flags [envvar]\n"
	"    - read all variables in short form\n"
	"\n"
	"tdx_secboot_get prop [envvar]\n"
	"    - read single variable\n"
	"      with 'envvar': store property value into variable\n"
	"      exit code 16 denotes an unknown property"
);
