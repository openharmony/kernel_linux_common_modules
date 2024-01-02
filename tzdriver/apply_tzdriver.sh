#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2022 Huawei Device Co., Ltd.
#

set -e

OHOS_SOURCE_ROOT=$1
KERNEL_BUILD_ROOT=$2
PRODUCT_NAME=$3
KERNEL_VERSION=$4
TZDRIVER_SOURCE_ROOT=$OHOS_SOURCE_ROOT/kernel/linux/common_modules/tzdriver

function main()
{
    pushd .

    if [ ! -d "$KERNEL_BUILD_ROOT/drivers/tzdriver" ]; then
        mkdir $KERNEL_BUILD_ROOT/drivers/tzdriver
    fi

    cd $KERNEL_BUILD_ROOT/drivers/tzdriver
    ln -s -f $(realpath --relative-to=$KERNEL_BUILD_ROOT/drivers/tzdriver/  $TZDRIVER_SOURCE_ROOT)/* ./

    popd
}

main
