// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2025 Toradex */

#include <asm/arch/clock.h>
#include <asm/arch/ddr.h>
#include <asm/arch/mu.h>
#include <asm/arch/sys_proto.h>
#include <asm/arch/trdc.h>
#include <asm/io.h>
#include <asm/mach-imx/boot_mode.h>
#include <asm/mach-imx/ele_api.h>
#include <asm/sections.h>
#include <command.h>
#include <cpu_func.h>
#include <init.h>
#include <power/pf9453.h>
#include <power/pmic.h>
#include <spl.h>

DECLARE_GLOBAL_DATA_PTR;

int spl_board_boot_device(enum boot_device boot_dev_spl)
{
	return BOOT_DEVICE_BOOTROM;
}

void spl_board_init(void)
{
	int ret;

	ret = ele_start_rng();
	if (ret)
		printf("Fail to start RNG: %d\n", ret);
}

void spl_dram_init(void)
{
	struct dram_timing_info *ptiming = &dram_timing;

	printf("DDR: %uMTS\n", ptiming->fsp_msg[0].drate);
	ddr_init(ptiming);
}

int power_init_board(void)
{
	struct udevice *dev;
	int ret;
	unsigned int buck_val;

	ret = pmic_get("pmic@32", &dev);
	if (ret == -ENODEV) {
		puts("No pf9453@32\n");
		return 0;
	}
	if (ret != 0)
		return ret;

	/* enable DVS control through PMIC_STBY_REQ */
	pmic_reg_write(dev, PF9453_BUCK2CTRL, 0x59);

	if (is_voltage_mode(VOLT_LOW_DRIVE)) {
		buck_val = 0x10; /* 0.8v for Low drive mode */
		printf("PMIC: Low Drive Voltage Mode\n");
	} else if (is_voltage_mode(VOLT_NOMINAL_DRIVE)) {
		buck_val = 0x14; /* 0.85v for Nominal drive mode */
		printf("PMIC: Nominal Voltage Mode\n");
	} else {
		buck_val = 0x18; /* 0.9v for Over drive mode */
		printf("PMIC: Over Drive Voltage Mode\n");
	}

	pmic_reg_write(dev, PF9453_BUCK2OUT, buck_val);

	/* set standby voltage to 0.65v */
	pmic_reg_write(dev, PF9453_BUCK2OUT_STBY, 0x4);

	ret = pmic_reg_read(dev, PF9453_CONFIG1);
	if (ret < 0)
		return ret;

	/* The RST timer default is 8sec and too long, so change to 100ms */
	pmic_reg_write(dev, PF9453_CONFIG1, ~PF9453_RESETKEY_TIMER_MASK & ret);

	/* set WDOG_B_CFG to cold reset */
	pmic_reg_write(dev, PF9453_RESET_CTRL, 0xA0);

	return 0;
}

void board_init_f(ulong dummy)
{
	int ret;

	/* TODO: BSS clear already done in crt0_64.S. Verify during bringup */
	memset(__bss_start, 0, __bss_end - __bss_start);

	timer_init();

	arch_cpu_init();

	board_early_init_f();

	spl_early_init();

	preloader_console_init();

	gd->arch.soc_rev = -1;
	gd->arch.lifecycle = -1;

	ret = imx9_probe_mu();
	if (ret)
		printf("Fail to init ELE API\n");

	printf("SOC: 0x%x\n", gd->arch.soc_rev);
	printf("LC: 0x%x\n", gd->arch.lifecycle);

	clock_init_late();

	power_init_board();

	if (!is_voltage_mode(VOLT_LOW_DRIVE))
		set_arm_core_max_clk();

	/* Init power of mix */
	soc_power_init();

	/* Setup TRDC for DDR access */
	trdc_init();

	/* DDR initialization */
	spl_dram_init();

	if (IS_ENABLED(CONFIG_IMX93)) {
		/* Put M33 into CPUWAIT for following kick */
		ret = m33_prepare();
		if (ret)
			printf("Fail to prepare M33\n");
	}

	board_init_r(NULL, 0);
}
