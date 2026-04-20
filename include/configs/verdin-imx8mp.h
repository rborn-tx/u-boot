/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright 2022 Toradex
 */

#ifndef __VERDIN_IMX8MP_H
#define __VERDIN_IMX8MP_H

#include <asm/arch/imx-regs.h>
#include <linux/sizes.h>

#define CFG_SYS_UBOOT_BASE	\
	(QSPI0_AMBA_BASE + CONFIG_SYS_MMCSD_RAW_MODE_U_BOOT_SECTOR * 512)

#ifdef CONFIG_SPL_BUILD

/* malloc f used before GD_FLG_FULL_MALLOC_INIT set */
#define CFG_MALLOC_F_ADDR				0x184000
/* For RAW image gives a error info not panic */

#endif /* CONFIG_SPL_BUILD */

#define MEM_LAYOUT_ENV_SETTINGS \
	"fdt_addr_r=0x50200000\0" \
	"kernel_addr_r=" __stringify(CONFIG_SYS_LOAD_ADDR) "\0" \
	"kernel_comp_addr_r=0x40200000\0" \
	"kernel_comp_size=0x08000000\0" \
	"ramdisk_addr_r=0x50300000\0" \
	"scriptaddr=0x50280000\0"

#ifdef CONFIG_FASTBOOT_FLASH
# ifndef CONFIG_FASTBOOT_FLASH_MMC_DEV
#  error CONFIG_FASTBOOT_FLASH_MMC_DEV must be defined
# endif
#define FASTBOOT_ENV_SETTINGS \
	"fastboot_partition_alias_all=" \
		__stringify(CONFIG_FASTBOOT_FLASH_MMC_DEV) ".0:0\0" \
	"fastboot_partition_alias_bootloader=" \
		__stringify(CONFIG_FASTBOOT_FLASH_MMC_DEV) ".1:0\0" \
	"fastboot_default_buf_addr=" \
		__stringify(CONFIG_FASTBOOT_BUF_ADDR) "\0" \
	"fastboot_default_buf_size=" \
		__stringify(CONFIG_FASTBOOT_BUF_SIZE) "\0" \
	"emmc_dev=" __stringify(CONFIG_FASTBOOT_FLASH_MMC_DEV) "\0" \
	"emmc_ack=1\0"
#else
#define FASTBOOT_ENV_SETTINGS
#endif

/* Enable Distro Boot */
#define BOOT_TARGET_DEVICES(func) \
	func(MMC, mmc, 1) \
	func(MMC, mmc, 2) \
	func(DHCP, dhcp, na)
#include <config_distro_bootcmd.h>

/* Initial environment variables */
#define CFG_EXTRA_ENV_SETTINGS \
	BOOTENV \
	MEM_LAYOUT_ENV_SETTINGS \
	FASTBOOT_ENV_SETTINGS \
	"boot_script_dhcp=boot.scr\0" \
	"console=ttymxc2\0" \
	"fdt_board=dev\0" \
	"initrd_addr=0x43800000\0" \
	"initrd_high=0xffffffffffffffff\0" \
	"update_uboot=askenv confirm Did you load flash.bin (y/N)?; " \
		"if test \"$confirm\" = \"y\"; then " \
		"setexpr blkcnt ${filesize} + 0x1ff && setexpr blkcnt " \
		"${blkcnt} / 0x200; mmc dev 2 1; mmc write ${loadaddr} 0x0 " \
		"${blkcnt}; fi\0"

#define CFG_SYS_INIT_RAM_ADDR	0x40000000
#define CFG_SYS_INIT_RAM_SIZE	SZ_512K

/* i.MX 8M Plus supports max. 8GB memory in two albeit concecutive banks */
#define CFG_SYS_SDRAM_BASE		0x40000000
#define PHYS_SDRAM			0x40000000
#define PHYS_SDRAM_SIZE			(SZ_2G + SZ_1G)
#define PHYS_SDRAM_2			0x100000000
#define PHYS_SDRAM_2_SIZE		(SZ_4G + SZ_1G)

#endif /* __VERDIN_IMX8MP_H */
