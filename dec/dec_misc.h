// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 */

#ifndef _DEC_MISC_H
#define _DEC_MISC_H

#include <linux/ioctl.h>
#include <linux/types.h>
#include <stdbool.h>

#define MAX_PATH_NUM 8

#define DEV_DEC_MINOR 0x25
#define DEC_IOCTL_BASE 's'
#define SET_POLICY_ID 1
#define DEL_POLICY_ID 2
#define QUERY_POLICY_ID 3
#define CHECK_POLICY_ID 4
#define DESTROY_POLICY_ID 5
#define CONSTRAINT_POLICY_ID 6
#define DENY_POLICY_ID 7

struct path_info {
    char* path;
    uint32_t path_len;
    uint32_t mode;
    bool ret_flag;
};

struct dec_policy_info {
    uint64_t tokenid;
    struct path_info path[MAX_PATH_NUM];
    uint32_t path_num;
    bool persist_flag;
};

#define SET_DEC_POLICY_CMD \
    _IOWR(DEC_IOCTL_BASE, SET_POLICY_ID, struct dec_policy_info)
#define DEL_DEC_POLICY_CMD \
    _IOWR(DEC_IOCTL_BASE, DEL_POLICY_ID, struct dec_policy_info)
#define QUERY_DEC_POLICY_CMD \
    _IOWR(DEC_IOCTL_BASE, QUERY_POLICY_ID, struct dec_policy_info)
#define CHECK_DEC_POLICY_CMD \
    _IOWR(DEC_IOCTL_BASE, CHECK_POLICY_ID, struct dec_policy_info)
#define CONSTRAINT_DEC_POLICY_CMD \
    _IOW(DEC_IOCTL_BASE, CONSTRAINT_POLICY_ID, struct dec_policy_info)
#define DENY_DEC_POLICY_CMD \
    _IOWR(DEC_IOCTL_BASE, DENY_POLICY_ID, struct dec_policy_info)
#define DESTROY_DEC_POLICY_CMD \
    _IOW(DEC_IOCTL_BASE, DESTROY_POLICY_ID, uint64_t)

#endif /* _DEC_MISC_H */