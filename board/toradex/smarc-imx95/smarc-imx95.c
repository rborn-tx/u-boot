// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2025 Toradex */

#include <asm/arch-imx9/ccm_regs.h>
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
#include <linux/bitops.h>
#include <scmi_protocols.h>
#include <usb.h>

#include "../common/tdx-cfg-block.h"

DECLARE_GLOBAL_DATA_PTR;

/* TODO: For the SMARC Dev Board, the USB TCPC code must be removed. */
#ifdef TEST_ON_VERDIN_EVK
#include "../../freescale/common/tcpc.h"

#if IS_ENABLED(CONFIG_USB_TCPC)
struct tcpc_port port;
struct tcpc_port_config port_config = {
	.i2c_bus = 6, /* i2c7 */
	.addr = 0x52,
	.port_type = TYPEC_PORT_DRP,
	.disable_pd = true,
};

ulong tca_base;

void tca_mux_select(enum typec_cc_polarity pol)
{
	u32 val;

	if (!tca_base)
		return;

	/* reset XBar block */
	setbits_le32(tca_base, BIT(9));

	/* Set OP mode to System configure Mode */
	clrbits_le32(tca_base + 0x10, 0x3);

	val = readl(tca_base + 0x30);

	WARN_ON((val & GENMASK(1, 0)) != 0x3);
	WARN_ON((val & BIT(2)) != 0);
	WARN_ON((val & BIT(3)) != 0);
	WARN_ON((val & BIT(4)) != 0);

	printf("tca pstate 0x%x\n", val);

	setbits_le32(tca_base + 0x18, BIT(3));
	udelay(1);

	if (pol == TYPEC_POLARITY_CC1)
		clrbits_le32(tca_base + 0x18, BIT(2));
	else
		setbits_le32(tca_base + 0x18, BIT(2));

	udelay(1);

	clrbits_le32(tca_base + 0x18, BIT(3));
}

static void setup_typec(void)
{
	int ret;

	tca_base = USB1_BASE_ADDR + 0xfc000;

	ret = tcpc_init(&port, port_config, &tca_mux_select);
	if (ret) {
		printf("%s: tcpc init failed, err=%d\n", __func__, ret);
		return;
	}
}
#endif
#endif /* TEST_ON_VERDIN_EVK */

#if IS_ENABLED(CONFIG_USB_DWC3)

#define PHY_CTRL0			0xF0040
#define PHY_CTRL0_REF_SSP_EN		BIT(2)
#define PHY_CTRL0_FSEL_MASK		GENMASK(10, 5)
#define PHY_CTRL0_FSEL_24M		0x2a
#define PHY_CTRL0_FSEL_100M		0x27
#define PHY_CTRL0_SSC_RANGE_MASK	GENMASK(23, 21)
#define PHY_CTRL0_SSC_RANGE_4003PPM	(0x2 << 21)

#define PHY_CTRL1			0xF0044
#define PHY_CTRL1_RESET			BIT(0)
#define PHY_CTRL1_COMMONONN		BIT(1)
#define PHY_CTRL1_ATERESET		BIT(3)
#define PHY_CTRL1_DCDENB		BIT(17)
#define PHY_CTRL1_CHRGSEL		BIT(18)
#define PHY_CTRL1_VDATSRCENB0		BIT(19)
#define PHY_CTRL1_VDATDETENB0		BIT(20)

#define PHY_CTRL2			0xF0048
#define PHY_CTRL2_TXENABLEN0		BIT(8)
#define PHY_CTRL2_OTG_DISABLE		BIT(9)

#define PHY_CTRL6			0xF0058
#define PHY_CTRL6_RXTERM_OVERRIDE_SEL	BIT(29)
#define PHY_CTRL6_ALT_CLK_EN		BIT(1)
#define PHY_CTRL6_ALT_CLK_SEL		BIT(0)

static struct dwc3_device dwc3_device_data = {
	.maximum_speed = USB_SPEED_HIGH,
	.base = USB1_BASE_ADDR,
	.dr_mode = USB_DR_MODE_PERIPHERAL,
	.index = 0,
	.power_down_scale = 2,
};

int dm_usb_gadget_handle_interrupts(struct udevice *dev)
{
	dwc3_uboot_handle_interrupt(dev);
	return 0;
}

static void dwc3_nxp_usb_phy_init(struct dwc3_device *dwc3)
{
	u32 value;

	/* USB3.0 PHY signal fsel for 24M ref */
	value = readl(dwc3->base + PHY_CTRL0);
	value &= ~PHY_CTRL0_FSEL_MASK;
	value |= FIELD_PREP(PHY_CTRL0_FSEL_MASK, PHY_CTRL0_FSEL_24M);
	writel(value, dwc3->base + PHY_CTRL0);

	/* Disable alt_clk_en and use internal MPLL clocks */
	value = readl(dwc3->base + PHY_CTRL6);
	value &= ~(PHY_CTRL6_ALT_CLK_SEL | PHY_CTRL6_ALT_CLK_EN);
	writel(value, dwc3->base + PHY_CTRL6);

	value = readl(dwc3->base + PHY_CTRL1);
	value &= ~(PHY_CTRL1_VDATSRCENB0 | PHY_CTRL1_VDATDETENB0);
	value |= PHY_CTRL1_RESET | PHY_CTRL1_ATERESET;
	writel(value, dwc3->base + PHY_CTRL1);

	value = readl(dwc3->base + PHY_CTRL0);
	value |= PHY_CTRL0_REF_SSP_EN;
	writel(value, dwc3->base + PHY_CTRL0);

	value = readl(dwc3->base + PHY_CTRL2);
	value |= PHY_CTRL2_TXENABLEN0 | PHY_CTRL2_OTG_DISABLE;
	writel(value, dwc3->base + PHY_CTRL2);

	udelay(10);

	value = readl(dwc3->base + PHY_CTRL1);
	value &= ~(PHY_CTRL1_RESET | PHY_CTRL1_ATERESET);
	writel(value, dwc3->base + PHY_CTRL1);
}
#endif

static int imx9_scmi_power_domain_enable(u32 domain, bool enable)
{
	return scmi_pwd_state_set(gd->arch.scmi_dev, 0, domain, enable ? 0 : BIT(30));
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

#ifdef TEST_ON_VERDIN_EVK
	if (IS_ENABLED(CONFIG_USB_TCPC))
		setup_typec();
#endif

	return 0;
}

int board_usb_init(int index, enum usb_init_type init)
{
	int ret = 0;

	if (index == 0) {
		switch (init) {
		case USB_INIT_DEVICE:
			ret = imx9_scmi_power_domain_enable(IMX95_PD_HSIO_TOP, true);
			if (ret)
				goto error;

			dwc3_nxp_usb_phy_init(&dwc3_device_data);

#ifdef TEST_ON_VERDIN_EVK
			if (IS_ENABLED(CONFIG_USB_TCPC)) {
				ret = tcpc_setup_ufp_mode(&port);
				if (ret)
					goto error;
			}
#endif

			ret = dwc3_uboot_init(&dwc3_device_data);
			if (ret)
				goto error;
		break;
		case USB_INIT_HOST:
#ifdef TEST_ON_VERDIN_EVK
			if (IS_ENABLED(CONFIG_USB_TCPC))
				return tcpc_setup_dfp_mode(&port);
#endif
		break;
		default:
			return -1;
		}
	}

	return 0;
error:
	printf("Board USB init failed: %d\n", ret);
	return ret;
}

int board_usb_cleanup(int index, enum usb_init_type init)
{
	int ret = 0;

	if (index == 0) {
		switch (init) {
		case USB_INIT_DEVICE:
				dwc3_uboot_exit(index);
		break;
		case USB_INIT_HOST:
#ifdef TEST_ON_VERDIN_EVK
			if (IS_ENABLED(CONFIG_USB_TCPC))
				ret = tcpc_disable_src_vbus(&port);
#endif
		break;
		default:
			return -1;
		}
	}

	return ret;
}

void board_quiesce_devices(void)
{
	int ret = 0;

	ret = imx9_scmi_power_domain_enable(IMX95_PD_HSIO_TOP, false);
	if (ret)
		printf("%s: Failed to disable PD HSIO for USB: %d\n", __func__, ret);
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
