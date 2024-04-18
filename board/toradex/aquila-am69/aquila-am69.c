// SPDX-License-Identifier: GPL-2.0-only
/*
 * Board specific initialization for Aquila AM69 SoM
 *
 * Copyright 2024 Toradex - https://www.toradex.com/
 */

#include <asm/arch/hardware.h>
#include <asm/io.h>
#include <dm.h>
#include <env.h>
#include <spl.h>

#include "../../../arch/arm/mach-k3/common_fdt.h"
#include "../common/tdx-common.h"

DECLARE_GLOBAL_DATA_PTR;

int board_init(void)
{
	return 0;
}

int dram_init(void)
{
	s32 ret;

	ret = fdtdec_setup_mem_size_base_lowest();
	if (ret)
		printf("Error setting up mem size and base. %d\n", ret);

	return ret;
}

int dram_init_banksize(void)
{
	s32 ret;

	ret = fdtdec_setup_memory_banksize();
	if (ret)
		printf("Error setting up memory banksize. %d\n", ret);

	return ret;
}

phys_size_t board_get_usable_ram_top(phys_size_t total_size)
{
#ifdef CONFIG_PHYS_64BIT
	/* Limit RAM used by U-Boot to the DDR low region */
	if (gd->ram_top > 0x100000000)
		return 0x100000000;
#endif

	return gd->ram_top;
}

#if defined(CONFIG_OF_LIBFDT) && defined(CONFIG_OF_BOARD_SETUP)
int ft_board_setup(void *blob, struct bd_info *bd)
{
	int ret;

	ret = fdt_fixup_msmc_ram_k3(blob);
	if (ret)
		return ret;

	return ft_common_board_setup(blob, bd);
}
#endif

void spl_board_init(void)
{
	struct udevice *dev;
	int ret;

	if (IS_ENABLED(CONFIG_ESM_K3)) {
		ret = uclass_get_device_by_name(UCLASS_MISC, "esm@700000",
						&dev);
		if (ret)
			printf("MISC init for esm@700000 failed: %d\n", ret);

		ret = uclass_get_device_by_name(UCLASS_MISC, "esm@40800000",
						&dev);
		if (ret)
			printf("MISC init for esm@40800000 failed: %d\n", ret);

		ret = uclass_get_device_by_name(UCLASS_MISC, "esm@42080000",
						&dev);
		if (ret)
			printf("MISC init for esm@42080000 failed: %d\n", ret);
	}

	if (IS_ENABLED(CONFIG_ESM_PMIC)) {
		ret = uclass_get_device_by_driver(UCLASS_MISC,
						  DM_DRIVER_GET(pmic_esm),
						  &dev);
		if (ret)
			printf("ESM PMIC init failed: %d\n", ret);
	}
}
