// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 */

#ifndef _CODE_SIGN_EXT_H
#define _CODE_SIGN_EXT_H

/*
 * code_sign_ext.c
 */
void code_sign_check_descriptor(const struct inode *inode,
    const void *desc, int *ret);

void code_sign_before_measurement(void *_desc, int *ret);

void code_sign_after_measurement(void *_desc, int version);

#endif /* _CODE_SIGN_H */
