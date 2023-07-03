/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 *
 * Description: Definitions for the NewIP Hooks
 * Register module.
 *
 * Author: Yang Yanjun <yangyanjun@huawei.com>
 *
 * Data: 2022-09-20
 */
#ifndef _NIP_HOOKS_REGISTER_H
#define _NIP_HOOKS_REGISTER_H

#ifdef CONFIG_NEWIP_HOOKS
int __init ninet_hooks_init(void);
#endif

#endif /* _NIP_HOOKS_REGISTER_H */
