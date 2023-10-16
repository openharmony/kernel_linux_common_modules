#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2023 Huawei Device Co., Ltd.
#

set -e

OHOS_SOURCE_ROOT=$1
KERNEL_BUILD_ROOT=$2
PRODUCT_NAME=$3
KERNEL_VERSION=$4
CODE_SIGN_SOURCE_ROOT=$OHOS_SOURCE_ROOT/kernel/linux/common_modules/code_sign

function main()
{
	pushd .

	if [ ! -d "$KERNEL_BUILD_ROOT/fs/code_sign" ]; then
		mkdir $KERNEL_BUILD_ROOT/fs/code_sign
	fi

	cd $KERNEL_BUILD_ROOT/fs/code_sign
	ln -s -f $(realpath --relative-to=$KERNEL_BUILD_ROOT/fs/code_sign  $CODE_SIGN_SOURCE_ROOT)/* ./

	popd
}

main
