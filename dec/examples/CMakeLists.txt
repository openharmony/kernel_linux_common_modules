# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2026 Huawei Device Co., Ltd.

cmake_minimum_required(VERSION 3.10)

project(dec_examples)

# compile toolchains
# ./prebuilts/ohos-sdk/linux/${version}/native/build-tools/cmake/bin/cmake \
#     -DCMAKE_TOOLCHAIN_FILE=./prebuilts/ohos-sdk/linux/${version}/native/build/cmake/ohos.toolchain.cmake \
#     -DOHOS_STL=c++_static \
#     -DOHOS_PLATFORM=OHOS \
#     -DOHOS_ARCH=armeabi-v7a

#compile dectool
add_executable(dectool
    dectool.cpp
    dec_test.cpp
    token_setproc.cpp
)
