#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2023 Huawei Device Co., Ltd.
#

set -e

OHOS_SOURCE_ROOT=$1
KERNEL_BUILD_ROOT=$2
PRODUCT_NAME=$3
KERNEL_VERSION=$4
CED_SOURCE_ROOT=$OHOS_SOURCE_ROOT/kernel/linux/common_modules/container_escape_detection

function main()
{
    pushd .

    if [ ! -d " $KERNEL_BUILD_ROOT/security/container_escape_detection" ]; then
        mkdir $KERNEL_BUILD_ROOT/security/container_escape_detection
    fi

    cd $KERNEL_BUILD_ROOT/security/container_escape_detection
    ln -s -f $(realpath --relative-to=$KERNEL_BUILD_ROOT/security/container_escape_detection/  $CED_SOURCE_ROOT)/* ./

    popd
}

main
