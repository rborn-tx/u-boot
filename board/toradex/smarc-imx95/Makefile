# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2025 Toradex

obj-y += smarc-imx95.o

ifdef CONFIG_SPL_BUILD
obj-y += spl.o
endif

# TODO: For the SMARC Dev Board, the USB TCPC code must be removed, the below
# file was included only to test on the Verdin-EVK ans has the TCPC functions
# declarations.
obj-y += ../../freescale/common/
