#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2022 Huawei Device Co., Ltd.
#

set -e

OHOS_SOURCE_ROOT=$1
KERNEL_BUILD_ROOT=$2
PRODUCT_NAME=$3
KERNEL_VERSION=$4
XPM_SOURCE_ROOT=$OHOS_SOURCE_ROOT/kernel/linux/common_modules/xpm

function main()
{
    pushd .

    if [ ! -d " $KERNEL_BUILD_ROOT/security/xpm" ]; then
        mkdir $KERNEL_BUILD_ROOT/security/xpm
    fi

    cd $KERNEL_BUILD_ROOT/security/xpm
    ln -s -f $(realpath --relative-to=$KERNEL_BUILD_ROOT/security/xpm/  $XPM_SOURCE_ROOT)/* ./

    popd
}

main
