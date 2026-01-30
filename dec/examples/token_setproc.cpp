// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 */

#include "token_setproc.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define ACCESS_TOKENID_GET_TOKENID \
    _IOR(ACCESS_TOKEN_ID_IOCTL_BASE, GET_TOKEN_ID, uint64_t)
#define ACCESS_TOKENID_SET_TOKENID \
    _IOW(ACCESS_TOKEN_ID_IOCTL_BASE, SET_TOKEN_ID, uint64_t)
#define ACCESS_TOKENID_GET_FTOKENID \
    _IOR(ACCESS_TOKEN_ID_IOCTL_BASE, GET_FTOKEN_ID, uint64_t)
#define ACCESS_TOKENID_SET_FTOKENID \
    _IOW(ACCESS_TOKEN_ID_IOCTL_BASE, SET_FTOKEN_ID, uint64_t)

#define INVAL_TOKEN_ID    0x0
#define TOKEN_ID_LOWMASK  0xffffffff

const uint64_t SET_PROC_FD_TAG = 0xD005A01;

uint64_t GetSelfTokenID(void)
{
    uint64_t token = INVAL_TOKEN_ID;
    int fd = open(TOKENID_DEVNODE, O_RDWR);
    if (fd < 0) {
        return INVAL_TOKEN_ID;
    }
    int ret = ioctl(fd, ACCESS_TOKENID_GET_TOKENID, &token);
    if (ret) {
        return INVAL_TOKEN_ID;
    }

    return token;
}

int SetSelfTokenID(uint64_t tokenID)
{
    int fd = open(TOKENID_DEVNODE, O_RDWR);
    if (fd < 0) {
        return ACCESS_TOKEN_OPEN_ERROR;
    }
    int ret = ioctl(fd, ACCESS_TOKENID_SET_TOKENID, &tokenID);
        if (ret) {
    return ret;
    }

    return ACCESS_TOKEN_OK;
}

uint64_t GetFirstCallerTokenID(void)
{
    uint64_t token = INVAL_TOKEN_ID;
    int fd = open(TOKENID_DEVNODE, O_RDWR);
    if (fd < 0) {
        return INVAL_TOKEN_ID;
    }
    int ret = ioctl(fd, ACCESS_TOKENID_GET_FTOKENID, &token);
    if (ret) {
        return INVAL_TOKEN_ID;
    }

    return token;
}

int SetFirstCallerTokenID(uint64_t tokenID)
{
    int fd = open(TOKENID_DEVNODE, O_RDWR);
    if (fd < 0) {
        return ACCESS_TOKEN_OPEN_ERROR;
    }
    int ret = ioctl(fd, ACCESS_TOKENID_SET_FTOKENID, &tokenID);
    if (ret) {
        return ret;
    }

    return ACCESS_TOKEN_OK;
}
 