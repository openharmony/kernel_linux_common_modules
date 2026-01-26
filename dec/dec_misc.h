// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 */

#ifndef _DEC_MISC_H
#define _DEC_MISC_H

#include <linux/ioctl.h>
#include <linux/types.h>
#include <linux/rbtree.h>
#include <linux/spinlock.h>

/*
 * DEC IOCTL command base identifier
 * Uses 's' (0x73) as the magic number for DEC subsystem IOCTL commands
 */
#define DEC_IOCTL_BASE 's'

/* DEC IOCTL command identifiers (subcodes) */
#define SET_RULE_ID          1   /* Add new DEC access rule */
#define DEL_RULE_ID          2   /* Delete specific DEC rule */
#define QUERY_RULE_ID        3   /* Query persistent DEC rules */
#define CHECK_RULE_ID        4   /* Check temporary DEC rules */
#define DESTROY_RULE_ID      5   /* Destroy all rules for a token ID */
#define CONSTRAINT_RULE_ID   6   /* Add path to constraint tree */
#define DEL_BY_USER_RULE_ID  7   /* Delete rules by user ID */
#define SET_PREFIX_ID        8   /* Set constraint prefix path */

#define MAX_POLICY_NUM 8
#define DEC_POLICY_HEADER_RESERVED 64

enum {
    FLAG_FALSE = 0,
    FLAG_TRUE = 1,
};

struct path_info {
    __u64 path;
    __u32 path_len;
    __u32 mode;
    __u8 ret_flag;
};

struct dec_rule_s {
    __u64 tokenid;
    __u64 timestamp;
    struct path_info path[MAX_POLICY_NUM];
    __u32 path_num;
    __s32 user_id;
    __u64 reserved[DEC_POLICY_HEADER_RESERVED];
    __u8 persist_flag;
};

struct path_info_32 {
    __u32 path;
    __u32 path_len;
    __u32 mode;
    __u8 ret_flag;
};

struct dec_rule_s_32 {
    __u64 tokenid;
    __u64 timestamp;
    struct path_info_32 path[MAX_POLICY_NUM];
    __u32 path_num;
    __s32 user_id;
    __u64 reserved[DEC_POLICY_HEADER_RESERVED];
    __u8 persist_flag;
};

#define SET_DEC_RULE_CMD \
    _IOWR(DEC_IOCTL_BASE, SET_RULE_ID, struct dec_rule_s)
#define DEL_DEC_RULE_CMD \
    _IOWR(DEC_IOCTL_BASE, DEL_RULE_ID, struct dec_rule_s)
#define QUERY_DEC_RULE_CMD \
    _IOWR(DEC_IOCTL_BASE, QUERY_RULE_ID, struct dec_rule_s)
#define CHECK_DEC_RULE_CMD \
    _IOWR(DEC_IOCTL_BASE, CHECK_RULE_ID, struct dec_rule_s)
#define DESTROY_DEC_RULE_CMD \
    _IOWR(DEC_IOCTL_BASE, DESTROY_RULE_ID, struct dec_rule_s)
#define CONSTRAINT_DEC_RULE_CMD \
    _IOW(DEC_IOCTL_BASE, CONSTRAINT_RULE_ID, struct dec_rule_s)
#define DEL_DEC_RULE_BY_USER_CMD \
    _IOWR(DEC_IOCTL_BASE, DEL_BY_USER_RULE_ID, struct dec_rule_s)
#define SET_DEC_PREFIX_CMD \
    _IOWR(DEC_IOCTL_BASE, SET_PREFIX_ID, struct dec_rule_s)

#define SET_DEC_RULE_CMD_32 \
    _IOWR(DEC_IOCTL_BASE, SET_RULE_ID, struct dec_rule_s_32)
#define DEL_DEC_RULE_CMD_32 \
    _IOWR(DEC_IOCTL_BASE, DEL_RULE_ID, struct dec_rule_s_32)
#define QUERY_DEC_RULE_CMD_32 \
    _IOWR(DEC_IOCTL_BASE, QUERY_RULE_ID, struct dec_rule_s_32)
#define CHECK_DEC_RULE_CMD_32 \
    _IOWR(DEC_IOCTL_BASE, CHECK_RULE_ID, struct dec_rule_s_32)
#define DESTROY_DEC_RULE_CMD_32 \
    _IOWR(DEC_IOCTL_BASE, DESTROY_RULE_ID, struct dec_rule_s_32)
#define CONSTRAINT_DEC_RULE_CMD_32 \
    _IOW(DEC_IOCTL_BASE, CONSTRAINT_RULE_ID, struct dec_rule_s_32)
#define DEL_DEC_RULE_BY_USER_CMD_32 \
    _IOWR(DEC_IOCTL_BASE, DEL_BY_USER_RULE_ID, struct dec_rule_s_32)
#define SET_DEC_PREFIX_CMD_32 \
    _IOWR(DEC_IOCTL_BASE, SET_PREFIX_ID, struct dec_rule_s_32)

#endif /* _DEC_MISC_H */