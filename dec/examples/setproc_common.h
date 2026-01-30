// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 */

#ifndef DEC_SETPROC_COMMON_H
#define DEC_SETPROC_COMMON_H

#define ACCESS_TOKEN_OK              0
#define ACCESS_TOKEN_PARAM_INVALID   (-1)
#define ACCESS_TOKEN_OPEN_ERROR      (-2)

#define TOKENID_DEVNODE "/dev/access_token_id"
#define ACCESS_TOKEN_ID_IOCTL_BASE 'A'

enum {
    GET_TOKEN_ID = 1,
    SET_TOKEN_ID,
    GET_FTOKEN_ID,
    SET_FTOKEN_ID,
    ADD_PERMISSIONS,
    REMOVE_PERMISSIONS,
    GET_PERMISSION,
    SET_PERMISSION,
    ACCESS_TOKENID_MAX_NR,
};

#endif // DEC_SETPROC_COMMON_H