// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2025 Toradex */

#include <asm/arch/clock.h>
#include <asm/arch-imx9/imx93_pins.h>
#include <init.h>

#include "../common/tdx-cfg-block.h"

DECLARE_GLOBAL_DATA_PTR;

#define UART_PAD_CTRL	(PAD_CTL_DSE(6) | PAD_CTL_FSEL2)

static iomux_v3_cfg_t const uart_pads[] = {
	MX93_PAD_UART1_RXD__LPUART1_RX | MUX_PAD_CTRL(UART_PAD_CTRL),
	MX93_PAD_UART1_TXD__LPUART1_TX | MUX_PAD_CTRL(UART_PAD_CTRL),
};

int board_early_init_f(void)
{
	imx_iomux_v3_setup_multiple_pads(uart_pads, ARRAY_SIZE(uart_pads));

	return 0;
}

int board_init(void)
{
	set_clk_enet(ENET_125MHZ);

	return 0;
}

#if IS_ENABLED(CONFIG_OF_BOARD_FIXUP)
int board_fix_fdt(void *fdt)
{
	board_fix_fdt_fuse(fdt);

	return 0;
}
#endif

#if IS_ENABLED(CONFIG_OF_LIBFDT) && IS_ENABLED(CONFIG_OF_BOARD_SETUP)
int ft_board_setup(void *blob, struct bd_info *bd)
{
	return ft_common_board_setup(blob, bd);
}
#endif
