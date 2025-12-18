/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2025 Toradex */

#ifndef __LINO_IMX93_H
#define __LINO_IMX93_H

#include <linux/sizes.h>
#include <asm/arch/imx-regs.h>

#define CFG_SYS_INIT_RAM_ADDR	0x80000000
#define CFG_SYS_INIT_RAM_SIZE	0x200000

#define CFG_SYS_SDRAM_BASE	0x80000000
#define PHYS_SDRAM		0x80000000
#define PHYS_SDRAM_SIZE		0x80000000 /* 2GB DDR */

/* Using ULP WDOG for reset */
#define WDOG_BASE_ADDR		WDG3_BASE_ADDR

#endif
