#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2022 Huawei Device Co., Ltd.
#
# Description: Create a symbolic link for NewIP in Linux 5.10
#
# Author: Yang Yanjun <yangyanjun@huawei.com>
#
# Data: 2022-07-25
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
	ln -s -f $(realpath --relative-to=$KERNEL_BUILD_ROOT/include/linux      $NEWIP_SOURCE_ROOT/third_party/linux-5.10/include/linux)/*.h ./
	cd $KERNEL_BUILD_ROOT/include/net/netns
	ln -s -f $(realpath --relative-to=$KERNEL_BUILD_ROOT/include/net/netns  $NEWIP_SOURCE_ROOT/third_party/linux-5.10/include/net/netns)/*.h ./
	cd $KERNEL_BUILD_ROOT/include/net
	ln -s -f $(realpath --relative-to=$KERNEL_BUILD_ROOT/include/net        $NEWIP_SOURCE_ROOT/third_party/linux-5.10/include/net)/*.h ./
	cd $KERNEL_BUILD_ROOT/include/uapi/linux
	ln -s -f $(realpath --relative-to=$KERNEL_BUILD_ROOT/include/uapi/linux $NEWIP_SOURCE_ROOT/third_party/linux-5.10/include/uapi/linux)/*.h ./

	if [ ! -d "$KERNEL_BUILD_ROOT/net/newip" ]; then
		mkdir $KERNEL_BUILD_ROOT/net/newip
	fi

	cd $KERNEL_BUILD_ROOT/net/newip/
	ln -s -f $(realpath --relative-to=$KERNEL_BUILD_ROOT/net/newip  $NEWIP_SOURCE_ROOT/src/linux-5.10/net/newip)/* ./
	ln -s -f $(realpath --relative-to=$KERNEL_BUILD_ROOT/net/newip  $NEWIP_SOURCE_ROOT/src/common)/* ./
	ln -s -f $(realpath --relative-to=$KERNEL_BUILD_ROOT/net/newip  $NEWIP_SOURCE_ROOT/third_party/linux-5.10/net/newip)/* ./
	cd $KERNEL_BUILD_ROOT/include/uapi/linux
	ln -s -f $(realpath --relative-to=$KERNEL_BUILD_ROOT/include/uapi/linux $NEWIP_SOURCE_ROOT/src/common)/nip_addr.h nip_addr.h

	cd $KERNEL_BUILD_ROOT/drivers/net/
	ln -s -f $(realpath --relative-to=$KERNEL_BUILD_ROOT/drivers/net/  $NEWIP_SOURCE_ROOT/src/linux-5.10/drivers/net/bt)

	popd
}

main
