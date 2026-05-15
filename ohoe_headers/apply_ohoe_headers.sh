#!/bin/bash
# Copyright (c) 2025 Huawei Device Co., Ltd.
# OpenHarmony specific header files injection for Linux kernel
#
# This script injects OpenHarmony-specific header files that are not
# present in the upstream Linux kernel but are required by OpenHarmony
# kernel modifications.

set -e

OHOS_ROOT_PATH=$1
KERNEL_SRC_TMP_PATH=$2
DEVICE_NAME=$3
KERNEL_VERSION=$4

if [ -z "${OHOS_ROOT_PATH}" ] || [ -z "${KERNEL_SRC_TMP_PATH}" ]; then
    echo "Usage: $0 <ohos_root> <kernel_src> <device_name> <kernel_version>"
    exit 1
fi

# Define header files to inject (from linux-5.10)
HEADER_BASE="${OHOS_ROOT_PATH}/kernel/linux/linux-5.10/include/linux"

# Headers that are referenced by OpenHarmony kernel code
# but not present in upstream Linux-6.6
HEADERS=(
    "memcg_policy.h"
    "memcheck.h"
    "hyperhold_inf.h"
    "lowmem_dbg.h"
    "xpm.h"
    "xpm_types.h"
    "zswapd.h"
    "mm_purgeable.h"
    "reclaim_acct.h"
)

# Target directory in the kernel source tree
TARGET_DIR="${KERNEL_SRC_TMP_PATH}/include/linux"

echo "Applying OpenHarmony specific header files..."

# Create target directory if it doesn't exist
mkdir -p "${TARGET_DIR}"

# Copy each header file
for header in "${HEADERS[@]}"; do
    if [ -f "${HEADER_BASE}/${header}" ]; then
        cp "${HEADER_BASE}/${header}" "${TARGET_DIR}/${header}"
        echo "  Injected: ${header}"
    else
        echo "  Warning: ${header} not found in source, skipping"
    fi
done

# memory_group_manager.h comes from rk3568_patch (ARM Mali GPU memory management)
# This is only needed if GPU support is enabled
MGM_HEADER="${OHOS_ROOT_PATH}/kernel/linux/patches/linux-6.6/rk3568_patch/kernel.patch"

if [ -f "${MGM_HEADER}" ]; then
    # Extract memory_group_manager.h from the patch
    echo "  Extracting memory_group_manager.h from rk3568_patch..."
    awk '
        /\+\+\+ b\/include\/linux\/memory_group_manager.h/ {
            p = 1
            next
        }
        p && /^\+/ {
            print substr($0, 2)
            if (/^+ \*\/$/) exit
        }
        p && /^@/ { exit }
    ' "${MGM_HEADER}" > "${TARGET_DIR}/memory_group_manager.h"
    echo "  Injected: memory_group_manager.h (extracted from rk3568_patch)"
else
    echo "  Warning: memory_group_manager.h source not found, skipping"
fi

echo "OpenHarmony header files injection complete."
