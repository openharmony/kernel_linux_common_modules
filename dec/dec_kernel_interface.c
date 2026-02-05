// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 */

#include <linux/sched.h>
#include <linux/string.h>

#include "dec_kernel_interface.h"
#include "dec_constraint_tree.h"
#include "dec_path_tree.h"
#include "dec_common.h"
#include "dec_utils.h"
#include "dec_log.h"
#include "sysctl.h"

/* DEC enforcement modes */
#define DEC_MODE_ENFORCED 1    /* Enforce rules (deny access on violation) */
#define DEC_MODE_PERMISSIVE 0  /* Log violations but allow access */

/* Global DEC enforcement mode (0=permissive, 1=enforced) */
extern int dec_mode;

static int32_t dec_get_pid(void)
{
    struct task_struct *curr = current;
    return curr->pid;
}

static char *dec_get_pname(void)
{
    struct task_struct *curr = current;
    return curr->comm;
}

static char *mode_to_string(uint32_t mode)
{
    static char mode_str[32];
    mode_str[0] = '\0';

    if (mode == DEC_READ) {
        strcat(mode_str, "r");
    } else if (mode == DEC_WRITE) {
        strcat(mode_str, "w");
    } else if (mode == (DEC_READ | DEC_WRITE)) {
        strcat(mode_str, "rw");
    }

    return mode_str;
}

static bool dec_mode_is_enforced(void)
{
    return dec_mode == DEC_MODE_ENFORCED;
}

int dec_rule_query(struct path_tree_params *params)
{
    uint64_t tokenid;
    const char *path;
    uint32_t mode;
    bool is_persist;
    int ret = 0;

    if (!params || !params->path) {
        dec_loge("DEC: Invalid parameters for rule query (params=%p, path=%p)",
                 params, params ? params->path : NULL);
        return -EINVAL;
    }

    tokenid = params->tokenid & DEC_TOKENID_MASK;
    path = params->path;
    mode = params->mode;
    is_persist = params->persist_flag;

    if (is_path_valid(path) != 0) {
        dec_loge("DEC: Invalid path for rule query: %s", path);
        return -EINVAL;
    }

    /* Bypass check if path is not in constraint tree (not regulated) */
    if (!dec_constraint_query(path)) {
        return ret;
    }

    /* Perform actual permission check against path tree */
    if (!dec_path_tree_query(tokenid, path, mode, is_persist)) {
        ret = -EPERM;
    }

    if (ret) {
        dec_logw("dec denied for pid=%d pname=\"%s\" policy_path=%s policy_mode=%s permissive=%d", 
            dec_get_pid(), dec_get_pname(), path, mode_to_string(mode), !dec_mode_is_enforced());
    }

    /* In permissive mode, allow access even if permission check failed */
#ifdef CONFIG_SECURITY_DEC_DEVELOP
    if (!dec_mode_is_enforced()) {
        return 0;
    }
#endif
    return ret;
}