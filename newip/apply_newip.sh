#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2022 Huawei Device Co., Ltd.
#

set -e

OHOS_SOURCE_ROOT=$1
KERNEL_BUILD_ROOT=$2
PRODUCT_NAME=$3
KERNEL_VERSION=$4
NEWIP_SOURCE_ROOT=$OHOS_SOURCE_ROOT/kernel/linux/common_modules/newip

function main()
{
    pushd .

    cd $KERNEL_BUILD_ROOT/include/linux/
    ln -s -f $(realpath --relative-to=$KERNEL_BUILD_ROOT/include/linux       $NEWIP_SOURCE_ROOT/src/linux/include/linux)/*.h ./
    cd $KERNEL_BUILD_ROOT/include/net/netns
    ln -s -f $(realpath --relative-to=$KERNEL_BUILD_ROOT/include/net/netns   $NEWIP_SOURCE_ROOT/src/linux/include/net/netns)/*.h ./
    cd $KERNEL_BUILD_ROOT/include/net
    ln -s -f $(realpath --relative-to=$KERNEL_BUILD_ROOT/include/net         $NEWIP_SOURCE_ROOT/src/linux/include/net)/*.h ./
    cd $KERNEL_BUILD_ROOT/include/uapi/linux
    ln -s -f $(realpath --relative-to=$KERNEL_BUILD_ROOT/include/uapi/linux  $NEWIP_SOURCE_ROOT/src/linux/include/uapi/linux)/*.h ./
    cd $KERNEL_BUILD_ROOT/include/trace/hooks
    ln -s -f $(realpath --relative-to=$KERNEL_BUILD_ROOT/include/trace/hooks $NEWIP_SOURCE_ROOT/src/linux/include/trace/hooks)/*.h ./

    if [ ! -d " $KERNEL_BUILD_ROOT/net/newip" ]; then
        mkdir $KERNEL_BUILD_ROOT/net/newip
    fi

    cd $KERNEL_BUILD_ROOT/net/newip/
    ln -s -f $(realpath --relative-to=$KERNEL_BUILD_ROOT/net/newip   $NEWIP_SOURCE_ROOT/src/linux/net/newip)/* ./
    ln -s -f $(realpath --relative-to=$KERNEL_BUILD_ROOT/net/newip   $NEWIP_SOURCE_ROOT/src/common)/* ./
    cd $KERNEL_BUILD_ROOT/include/uapi/linux
    ln -s -f $(realpath --relative-to=$KERNEL_BUILD_ROOT/include/uapi/linux   $NEWIP_SOURCE_ROOT/src/common)/nip_addr.h nip_addr.h

    popd
}

main
