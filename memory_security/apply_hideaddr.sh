#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2022 Huawei Device Co., Ltd.
#
#Description: Create a symbolic link for memory_security in Linux 5.10
#

set -e

OHOS_SOURCE_ROOT=$1
KERNEL_BUILD_ROOT=$2
PRODUCT_NAME=$3
KERNEL_VERSION=$4
MEMORY_SECURITY_SOURCE_ROOT=$OHOS_SOURCE_ROOT/kernel/linux/common_modules/memory_security

function main()
{
	pushd .

	if [ ! -d "$KERNEL_BUILD_ROOT/fs/proc/memory_security" ]; then
		mkdir $KERNEL_BUILD_ROOT/fs/proc/memory_security
	fi

	cd $KERNEL_BUILD_ROOT/fs/proc/memory_security
	ln -s -f $(realpath --relative-to=$KERNEL_BUILD_ROOT/fs/proc/memory_security/   $MEMORY_SECURITY_SOURCE_ROOT)/* ./

	popd
}

main
