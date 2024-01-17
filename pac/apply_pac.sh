#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (c) 2023 Huawei Device Co., Ltd.
#

set -e

OHOS_SOURCE_ROOT=$1
KERNEL_BUILD_ROOT=$2
PRODUCT_NAME=$3
KERNEL_VERSION=$4
PAC_SOURCE_ROOT=$OHOS_SOURCE_ROOT/kernel/linux/common_modules/pac

function main()
{
    pushd .

    if [ ! -d " $KERNEL_BUILD_ROOT/arch/arm64/pac/src" ]; then
        mkdir -p $KERNEL_BUILD_ROOT/arch/arm64/pac/src
    fi

    if [ ! -d " $KERNEL_BUILD_ROOT/arch/arm64/pac/config" ]; then
        mkdir -p $KERNEL_BUILD_ROOT/arch/arm64/pac/config
    fi

    cd $KERNEL_BUILD_ROOT/arch/arm64/pac
    ln -s -f $(realpath --relative-to=$KERNEL_BUILD_ROOT/arch/arm64/pac  $PAC_SOURCE_ROOT)/Makefile ./Makefile

    cd $KERNEL_BUILD_ROOT/arch/arm64/pac/config
    ln -s -f $(realpath --relative-to=$KERNEL_BUILD_ROOT/arch/arm64/pac/config  $PAC_SOURCE_ROOT/config)/config.txt ./config.txt

    cd $KERNEL_BUILD_ROOT/arch/arm64/pac/src
    ln -s -f $(realpath --relative-to=$KERNEL_BUILD_ROOT/arch/arm64/pac/src  $PAC_SOURCE_ROOT/src)/* ./

    cd $KERNEL_BUILD_ROOT/arch/arm64/include/asm
    ln -s -f $(realpath --relative-to=$KERNEL_BUILD_ROOT/arch/arm64/include/asm  $PAC_SOURCE_ROOT/include)/* ./

    popd
}

main
