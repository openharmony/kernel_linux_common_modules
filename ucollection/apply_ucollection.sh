#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2023 Huawei Device Co., Ltd.
#
# Description: Create a symbolic link for Unified Collection Driver in Linux 5.10
#

set -e

OHOS_SOURCE_ROOT=$1
KERNEL_BUILD_ROOT=$2
PRODUCT_NAME=$3
KERNEL_VERSION=$4
UNIFIED_COLLECTION_SOURCE_ROOT=$OHOS_SOURCE_ROOT/kernel/linux/common_modules/ucollection

function main()
{
	pushd .

	echo "create link $KERNEL_BUILD_ROOT/drivers/staging/ucollection/"
	if [ ! -d "$KERNEL_BUILD_ROOT/drivers/staging/ucollection" ]; then
		mkdir $KERNEL_BUILD_ROOT/drivers/staging/ucollection
	fi

	cd $KERNEL_BUILD_ROOT/drivers/staging/ucollection/
	ln -s -f $(realpath --relative-to=$KERNEL_BUILD_ROOT/drivers/staging/ucollection/  $UNIFIED_COLLECTION_SOURCE_ROOT)/* ./

	popd
}

main
