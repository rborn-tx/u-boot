/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2025 Toradex */

#ifndef __IMX95_TORADEX_SMARC_H
#define __IMX95_TORADEX_SMARC_H

#include <linux/sizes.h>
#include <asm/arch/imx-regs.h>

#define CFG_SYS_UBOOT_BASE	\
	(QSPI0_AMBA_BASE + CONFIG_SYS_MMCSD_RAW_MODE_U_BOOT_SECTOR * 512)

#define SZ_14G	_AC(0x380000000, ULL)

#define CFG_SYS_INIT_RAM_ADDR	0x90000000
#define CFG_SYS_INIT_RAM_SIZE	SZ_2M

#define CFG_SYS_SDRAM_BASE	0x90000000
#define PHYS_SDRAM		0x90000000
#define PHYS_SDRAM_SIZE		(SZ_2G - SZ_256M)
#define PHYS_SDRAM_2_SIZE	SZ_14G

#define WDOG_BASE_ADDR	WDG3_BASE_ADDR

#endif
