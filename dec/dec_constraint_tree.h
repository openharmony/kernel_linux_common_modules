// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 */

#ifndef _DEC_CONSTRAINT_H
#define _DEC_CONSTRAINT_H

#include <linux/types.h>

bool dec_constraint_query(const char *path);
int dec_constraint_add(char *path);
#endif /* _DEC_CONSTRAINT_H */
