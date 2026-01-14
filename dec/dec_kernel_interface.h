// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 */

#ifndef _DEC_KERNEL_INTERFACE_H
#define _DEC_KERNEL_INTERFACE_H

#include <linux/types.h>
#include <linux/errno.h>

#include "dec_common.h"

int dec_rule_query(struct path_tree_params *params);
#endif /* _DEC_KERNEL_INTERFACE_H */