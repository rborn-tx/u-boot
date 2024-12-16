// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2025 Toradex */

#include <asm/arch/ccm_regs.h>
#include <asm/arch/clock.h>
#include <asm/arch/sys_proto.h>
#include <asm/arch-imx9/mu.h>
#include <asm/mach-imx/boot_mode.h>
#include <asm/mach-imx/ele_api.h>
#include <asm/sections.h>
#include <asm/global_data.h>
#include <clk.h>
#include <dt-bindings/clock/fsl,imx95-clock.h>
#include <dt-bindings/power/fsl,imx95-power.h>
#include <hang.h>
#include <init.h>
#include <log.h>
#include <scmi_agent.h>
#include <scmi_protocols.h>
#include <spl.h>

DECLARE_GLOBAL_DATA_PTR;

int spl_board_boot_device(enum boot_device boot_dev_spl)
{
	switch (boot_dev_spl) {
	case SD1_BOOT:
	case MMC1_BOOT:
		return BOOT_DEVICE_MMC1;
	case SD2_BOOT:
	case MMC2_BOOT:
		return BOOT_DEVICE_MMC2;
	case USB_BOOT:
		return BOOT_DEVICE_BOARD;
	case QSPI_BOOT:
		return BOOT_DEVICE_SPI;
	default:
		return BOOT_DEVICE_NONE;
	}
}

void spl_board_init(void)
{
	int ret;

	ret = ele_start_rng();
	if (ret)
		printf("Fail to start RNG: %d\n", ret);
}

void board_init_f(ulong dummy)
{
	u32 state = 0;
	int ret;

	if (IS_ENABLED(CONFIG_SPL_RECOVER_DATA_SECTION) && IS_ENABLED(CONFIG_SPL_BUILD))
		spl_save_restore_data();

	timer_init();

	/* Need dm_init() to run before any SCMI calls */
	spl_early_init();

	/* Need to enable SCMI drivers and ELE driver before console */
	ret = imx9_probe_mu();
	if (ret)
		hang(); /* MU not probed, nothing can be outputed, hang */

	arch_cpu_init();

	board_early_init_f();

	preloader_console_init();

	printf("SOC: 0x%x\n", gd->arch.soc_rev);
	printf("LC: 0x%x\n", gd->arch.lifecycle);

	/* Set ARM CPU freq to max rate */
	clock_init_late();

	/* Check DDR MIX is already powered up */
	ret = scmi_pwd_state_get(gd->arch.scmi_dev, IMX95_PD_DDR, &state);
	if (ret)
		printf("scmi_pwd_state_get Failed %d for DDRMIX\n", ret);
	else if (state == BIT(30))
		panic("DDRMIX is powered OFF, Please initialize DDR with OEI\n");

	board_init_r(NULL, 0);
}
