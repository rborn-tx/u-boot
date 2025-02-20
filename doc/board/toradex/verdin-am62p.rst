.. SPDX-License-Identifier: GPL-2.0-or-later
.. sectionauthor:: Parth Pancholi <parth.pancholi@toradex.com>

Verdin AM62P Module
==================

- SoM: https://www.toradex.com/computer-on-modules/verdin-arm-family/ti-am62p
- Carrier board: https://www.toradex.com/products/carrier-board/verdin-development-board-kit

Quick Start
-----------

- Setup environment variables
- Get binary-only TI Linux firmware
- Build the ARM trusted firmware binary
- Build the OPTEE binary
- Build U-Boot for the R5
- Build U-Boot for the A53
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

    $ export CROSS_COMPILE="$CROSS_COMPILE_64"
    $ make PLAT=k3 K3_PM_SYSTEM_SUSPEND=1 TARGET_BOARD=lite SPD=opteed

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
    $ make PLATFORM=k3-am62px CFG_ARM64_core=y

Build U-Boot for R5
-------------------

.. code-block:: bash

    $ export CROSS_COMPILE="$CROSS_COMPILE_32"
    $ export BINMAN_INDIRS=<path/to/ti-linux-firmware>
    $ make O=/tmp/verdin-am62p-r5 verdin-am62p_r5_defconfig
    $ make O=/tmp/verdin-am62p-r5

Build U-Boot for A53
--------------------

.. code-block:: bash

    $ export CROSS_COMPILE=$CROSS_COMPILE_64
    $ export BL31=<path/to/atf>/build/k3/lite/release/bl31.bin
    $ export TEE=<path/to/optee>/out/arm-plat-k3/core/tee-pager_v2.bin
    $ export BINMAN_INDIRS="<path/to/ti-linux-firmware> /tmp/verdin-am62p-r5"
    $ make O=/tmp/verdin-am62p-a53 verdin-am62p_r5_defconfig
    $ make O=/tmp/verdin-am62p-a53

Flash to eMMC
-------------

.. code-block:: console

    => mmc dev 0 1
    => fatload mmc 1 ${loadaddr} tiboot3.bin
    => mmc write ${loadaddr} 0x0 0x400
    => fatload mmc 1 ${loadaddr} tispl.bin
    => mmc write ${loadaddr} 0x400 0x1000
    => fatload mmc 1 ${loadaddr} u-boot.img
    => mmc write ${loadaddr} 0x1400 0x2000

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
