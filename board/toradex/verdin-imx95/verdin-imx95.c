// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2025 Toradex */

#include <asm/arch/clock.h>
#include <asm/arch/sys_proto.h>
#include <asm/global_data.h>
#include <asm/io.h>
#include <dt-bindings/power/fsl,imx95-power.h>
#include <dwc3-uboot.h>
#include <env.h>
#include <fdt_support.h>
#include <init.h>
#include <linux/bitfield.h>
#include <linux/delay.h>
#include <scmi_protocols.h>
#include <usb.h>

#include "../common/tdx-cfg-block.h"

DECLARE_GLOBAL_DATA_PTR;

static int imx9_scmi_power_domain_enable(u32 domain, bool enable)
{
	return scmi_pwd_state_set(gd->arch.scmi_dev, 0, domain, enable ? 0 : BIT(30));
}

static void netc_init(void)
{
	int ret;

	ret = imx9_scmi_power_domain_enable(IMX95_PD_NETC, true);
	if (ret) {
		printf("%s: Failed to enable PD NETC for Ethernet: %d\n", __func__, ret);
		return;
	}

	set_clk_netc(ENET_125MHZ);

	pci_init();
}

int board_early_init_f(void)
{
	/* UART1: A55 */
	init_uart_clk(0);

	return 0;
}

int board_init(void)
{
	int ret;

	ret = imx9_scmi_power_domain_enable(IMX95_PD_HSIO_TOP, true);
	if (ret) {
		printf("%s: Failed to enable PD HSIO for USB: %d\n", __func__, ret);
		return ret;
	}

	netc_init();

	return 0;
}

void board_quiesce_devices(void)
{
	int ret = 0;

	ret = imx9_scmi_power_domain_enable(IMX95_PD_HSIO_TOP, false);
	if (ret)
		printf("%s: Failed to disable PD HSIO for USB: %d\n", __func__, ret);

	ret = imx9_scmi_power_domain_enable(IMX95_PD_NETC, false);
	if (ret)
		printf("%s: Failed to disable PD NETC for Ethernet: %d\n", __func__, ret);
}

static void select_dt_from_module_version(void)
{
	char variant[32];
	char *env_variant = env_get("variant");
	bool is_wifi = false;

	if (IS_ENABLED(CONFIG_TDX_CFG_BLOCK)) {
		/*
		 * If we have a valid config block and it says we are a
		 * module with Wi-Fi/Bluetooth make sure we use the -wifi
		 * device tree.
		 */
		is_wifi = (tdx_hw_tag.prodid == VERDIN_IMX95H_8G_WIFI_BT_IT);
	}

	if (is_wifi)
		strlcpy(&variant[0], "wifi", sizeof(variant));
	else
		strlcpy(&variant[0], "nonwifi", sizeof(variant));

	if (strcmp(variant, env_variant)) {
		printf("Setting variant to %s\n", variant);
		env_set("variant", variant);
	}
}

int board_late_init(void)
{
	select_dt_from_module_version();

	return 0;
}

int board_phys_sdram_size(phys_size_t *size)
{
	*size = PHYS_SDRAM_SIZE + PHYS_SDRAM_2_SIZE;

	return 0;
}

#if IS_ENABLED(CONFIG_OF_LIBFDT) && IS_ENABLED(CONFIG_OF_BOARD_SETUP)
int ft_board_setup(void *blob, struct bd_info *bd)
{
	return ft_common_board_setup(blob, bd);
}
#endif
