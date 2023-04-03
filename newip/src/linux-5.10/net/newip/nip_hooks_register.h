/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 *
 * Definitions for the NewIP Hooks Register module.
 */
#ifndef _NIP_HOOKS_REGISTER_H
#define _NIP_HOOKS_REGISTER_H

#ifdef CONFIG_NEWIP_HOOKS
int ninet_hooks_register(void);
#endif

#endif /* _NIP_HOOKS_REGISTER_H */
