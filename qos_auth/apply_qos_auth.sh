#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2023 Huawei Device Co., Ltd.
#

set -e

OHOS_SOURCE_ROOT=$1
KERNEL_BUILD_ROOT=$2
PRODUCT_NAME=$3
KERNEL_VERSION=$4
QOS_AUTH_SOURCE_ROOT=$OHOS_SOURCE_ROOT/kernel/linux/common_modules/qos_auth

function main()
{
	pushd .

	cd $KERNEL_BUILD_ROOT/include/linux/sched
	ln -sf $(realpath --relative-to=$KERNEL_BUILD_ROOT/include/linux/sched  $QOS_AUTH_SOURCE_ROOT/include)/*.h ./

	if [ ! -d "$KERNEL_BUILD_ROOT/drivers/auth_ctl" ]; then
		mkdir $KERNEL_BUILD_ROOT/drivers/auth_ctl
	fi

	cd $KERNEL_BUILD_ROOT/drivers/auth_ctl
	ln -sf $(realpath --relative-to=$KERNEL_BUILD_ROOT/drivers/auth_ctl  $QOS_AUTH_SOURCE_ROOT/auth_ctl)/* ./

	popd
}

main
