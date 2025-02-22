// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright 2023 Toradex
 */

#ifndef __TDX_HARDEN_H
#define __TDX_HARDEN_H

/*
 * Sample device-tree configuring hardening:
 * / {
 *     chosen {
 *         toradex,secure-boot {    [if not present: disable Toradex hardening]
 *             disabled;                  [optional: disable Toradex hardening]
 *             bootloader-commands {
 *                 allow-open = <CMD_CAT_ALL>;
 *                 allow-closed = <CMD_CAT_NEEDED CMD_CAT_SAFE>;
 *                 deny-open = <CMD_CAT_ALL_UNSAFE>;    [optional, discouraged]
 *                 deny-closed = <CMD_CAT_ALL_UNSAFE>;  [optional, discouraged]
 *                 needed = <CMD_CAT_NEEDED>            [optional, discouraged]
 *             };
 *         };
 *     };
 * };
 */

/* Path of node in FDT containing all Secure Boot setup. */
#define TDX_SECBOOT_NODE_PATH \
        "/chosen/toradex,secure-boot"

/* Path of node in FDT containing command whitelist/blacklist. */
#define TDX_BOOTLDR_CMDS_NODE_PATH \
        "/chosen/toradex,secure-boot/bootloader-commands"

struct cmd_tbl;

int cmd_allowed_by_whitelist(struct cmd_tbl *cmd, int argc, char *const argv[]);

#ifdef CONFIG_TDX_SECBOOT_HARDENING
int tdx_hardening_enabled(void);
#else
static inline int tdx_hardening_enabled(void) {
	return 0;
}
#endif

/* from tdx-secboot (included here for convenience) */
int tdx_secboot_dev_is_open(void);

#endif	/* __TDX_HARDEN_H */
