// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 */

#ifndef _JIT_MEMORY_MODULE_H
#define _JIT_MEMORY_MODULE_H


#ifdef CONFIG_JIT_MEM_CONTROL
void jit_memory_register_hooks(void);

#else
inline void jit_memory_register_hooks(void)
{
}

#endif // CONFIG_JIT_MEM_CONTROL

#endif /* _JIT_MEMORY_MODULE_H */