/*
// SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 */

#ifndef _DEC_PATH_TREE_H
#define _DEC_PATH_TREE_H

#include <linux/types.h>

#include "dec_common.h"

enum delete_criteria {
    DELETE_BY_TOKENID = 1,  
    DELETE_BY_USERID,       
};

union dec_dectroy_params {
    struct {
        uint64_t tokenid;
    } tokeninfo;
    struct {
        int userid;
        const char *path;
    } userinfo;
};

struct dec_destroy_ctx {
    enum delete_criteria criteria;
    union dec_dectroy_params params;
    uint64_t timestamp;
};

bool dec_path_tree_query(uint64_t tokenid, const char *path, uint32_t mode, bool is_persist);
int dec_set_rule(struct path_tree_params *params);
int dec_delete_rule(uint64_t tokenid, const char *path, uint64_t timestamp);
int dec_destroy_rule_by_id(struct dec_destroy_ctx *ctx);

int dec_set_prefix(const char *prefix);
#endif /* _DEC_PATH_TREE_H */