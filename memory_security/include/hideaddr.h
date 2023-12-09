// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 */

#ifndef _HIDE_ADDR_MODULE_H
#define _HIDE_ADDR_MODULE_H


#ifdef CONFIG_HIDE_MEM_ADDRESS
void hideaddr_header_prefix_lhck_register(void);

#else
inline void hideaddr_header_prefix_lhck_register(void)
{
}

#endif // CONFIG_HIDE_MEM_ADDRESS

#endif /* _HIDE_ADDR_MODULE_H */