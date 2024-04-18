/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Configuration header file for Aquila AM69 SoM
 *
 * Copyright 2024 Toradex - https://www.toradex.com/
 */

#ifndef __CONFIG_AQUILA_AM69_H
#define __CONFIG_AQUILA_AM69_H

#define RAMDISK_ADDR_R			0x90300000
#define SCRIPTADDR			0x90280000

/* DDR Configuration */
#define CFG_SYS_SDRAM_BASE		0x80000000
#define CFG_SYS_SDRAM_BASE1		0x880000000

#define MEM_LAYOUT_ENV_SETTINGS \
	"fdt_addr_r=0x90200000\0" \
	"kernel_addr_r=" __stringify(CONFIG_SYS_LOAD_ADDR) "\0" \
	"kernel_comp_addr_r=0x80200000\0" \
	"kernel_comp_size=0x08000000\0" \
	"ramdisk_addr_r=" __stringify(RAMDISK_ADDR_R) "\0" \
	"scriptaddr=" __stringify(SCRIPTADDR) "\0"

#define BOOT_TARGETS	"mmc1 mmc0 dhcp"

#define EXTRA_ENV_DFUARGS \
	"dfu_alt_info_ram=" \
	"tispl.bin ram 0x80080000 0x200000;" \
	"u-boot.img ram 0x81000000 0x400000;" \
	"loadaddr ram " __stringify(CONFIG_SYS_LOAD_ADDR) " 0x80000;" \
	"scriptaddr ram " __stringify(SCRIPTADDR) " 0x80000;" \
	"ramdisk_addr_r ram " __stringify(RAMDISK_ADDR_R) " 0x8000000\0"

/* Incorporate settings into the U-Boot environment */
#define CFG_EXTRA_ENV_SETTINGS \
	EXTRA_ENV_DFUARGS \
	MEM_LAYOUT_ENV_SETTINGS \
	"boot_script_dhcp=boot.scr\0" \
	"boot_targets=" BOOT_TARGETS "\0" \
	"console=ttyS2\0" \
	"fdt_board=dev\0" \
	"update_tiboot3=askenv confirm Did you load tiboot3.bin (y/N)?; " \
		"if test \"$confirm\" = \"y\"; then " \
		"setexpr blkcnt ${filesize} + 0x1ff && setexpr blkcnt " \
		"${blkcnt} / 0x200; mmc dev 0 1; mmc write ${loadaddr} 0x0 " \
		"${blkcnt}; fi\0" \
	"update_tispl=askenv confirm Did you load tispl.bin (y/N)?; " \
		"if test \"$confirm\" = \"y\"; then " \
		"setexpr blkcnt ${filesize} + 0x1ff && setexpr blkcnt " \
		"${blkcnt} / 0x200; mmc dev 0 1; mmc write ${loadaddr} 0x800 " \
		"${blkcnt}; fi\0" \
	"update_uboot=askenv confirm Did you load u-boot.img (y/N)?; " \
		"if test \"$confirm\" = \"y\"; then " \
		"setexpr blkcnt ${filesize} + 0x1ff && setexpr blkcnt " \
		"${blkcnt} / 0x200; mmc dev 0 1; mmc write ${loadaddr} 0x1800 " \
		"${blkcnt}; fi\0"

#endif /* __CONFIG_AQUILA_AM69_H */
