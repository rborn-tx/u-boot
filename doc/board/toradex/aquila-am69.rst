.. SPDX-License-Identifier: GPL-2.0-only
.. sectionauthor:: Emanuele Ghidoli <emanuele.ghidoli@toradex.com>

Aquila AM69 Module
==================

Quick Start
-----------

- Setup environment variables
- Get binary-only TI Linux firmware
- Build the ARM trusted firmware binary
- Build the OPTEE binary
- Build U-Boot for the R5
- Build U-Boot for the A72
- Flash to eMMC
- Boot

Setup environment
-----------------

Suggested current toolchains are ARM 11.3 (https://developer.arm.com/downloads/-/arm-gnu-toolchain-downloads):

- https://developer.arm.com/-/media/Files/downloads/gnu/11.3.rel1/binrel/arm-gnu-toolchain-11.3.rel1-x86_64-arm-none-linux-gnueabihf.tar.xz
- https://developer.arm.com/-/media/Files/downloads/gnu/11.3.rel1/binrel/arm-gnu-toolchain-11.3.rel1-x86_64-aarch64-none-linux-gnu.tar.xz

.. code-block:: bash

    $ export CROSS_COMPILE_32=<path/to/arm/toolchain/bin/>arm-none-linux-gnueabihf-
    $ export CROSS_COMPILE_64=<path/to/arm64/toolchain/bin/>aarch64-none-linux-gnu-

Get the TI Linux Firmware
-------------------------

.. code-block:: bash

    $ echo "Downloading TI Linux Firmware..."
    $ git clone -b ti-linux-firmware https://git.ti.com/git/processor-firmware/ti-linux-firmware.git

Get and Build the ARM Trusted Firmware (Trusted Firmware A)
-----------------------------------------------------------

.. code-block:: bash

    $ echo "Downloading and building TF-A..."
    $ git clone https://git.trustedfirmware.org/TF-A/trusted-firmware-a.git
    $ cd trusted-firmware-a

Then build ATF (TF-A):

.. code-block:: bash

    $ export ARCH=aarch64
    $ export CROSS_COMPILE="$CROSS_COMPILE_64"
    $ make PLAT=k3 TARGET_BOARD=j784s4 SPD=opteed K3_USART=0x8

Get and Build OPTEE
-------------------

.. code-block:: bash

    $ echo "Downloading and building OPTEE..."
    $ git clone https://github.com/OP-TEE/optee_os.git
    $ cd optee_os

Then build OPTEE:

.. code-block:: bash

    $ export CROSS_COMPILE="$CROSS_COMPILE_32"
    $ export CROSS_COMPILE64="$CROSS_COMPILE_64"
    $ export CFG_CONSOLE_UART=0x8
    $ make PLATFORM=k3-j784s4 CFG_ARM64_core=y

Build U-Boot for R5
-------------------

.. code-block:: bash

    $ export ARCH=arm
    $ export CROSS_COMPILE="$CROSS_COMPILE_32"
    $ export BINMAN_INDIRS=<path/to/ti-linux-firmware>
    $ make O=/tmp/aquila-r5 aquila-am69_r5_config
    $ make O=/tmp/aquila-r5

Build U-Boot for A72
--------------------

.. code-block:: bash

    $ export ARCH=arm64
    $ export CROSS_COMPILE=$CROSS_COMPILE_64
    $ export BL31=<path/to/atf>/build/k3/j784s4/release/bl31.bin
    $ export TEE=<path/to/optee>/out/arm-plat-k3/core/tee-pager_v2.bin
    $ export BINMAN_INDIRS=<path/to/ti-linux-firmware>
    $ make O=/tmp/aquila-a72 aquila-am69_a72_config
    $ make O=/tmp/aquila-a72

Flash to eMMC
-------------

.. code-block:: console

    => mmc dev 0 1
    => fatload mmc 1 ${loadaddr} tiboot3.bin
    => mmc write ${loadaddr} 0x0 0x800
    => fatload mmc 1 ${loadaddr} tispl.bin
    => mmc write ${loadaddr} 0x800 0x1000
    => fatload mmc 1 ${loadaddr} u-boot.img
    => mmc write ${loadaddr} 0x1800 0x2000

As a convenience, instead of having to remember all those addresses and sizes,
one may also use the update U-Boot wrappers:

.. code-block:: console

    => tftpboot ${loadaddr} tiboot3.bin
    => run update_tiboot3

    => tftpboot ${loadaddr} tispl.bin
    => run update_tispl

    => tftpboot ${loadaddr} u-boot.img
    => run update_uboot

Boot
----

Output:

.. code-block:: console

TODO: add output from real HW.
