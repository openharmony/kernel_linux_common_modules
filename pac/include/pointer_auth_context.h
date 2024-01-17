// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 */

#ifndef __POINTER_AUTH_CONTEXT_H
#define __POINTER_AUTH_CONTEXT_H

struct pt_regs;

enum pac_pt_regs {
	REGS_X16 = 0,
	REGS_X17,
	REGS_LR,
	REGS_SP,
	REGS_PC,
	REGS_PSTATE,
};

void sign_thread_context(void *cpu_context);
void auth_thread_context(void *cpu_context);

void sign_exception_context_asm(void *regs);
void auth_exception_context_asm(void *regs);

int set_exception_context_register_asm(void *regs, int offset, u64 val);

#ifdef CONFIG_COMPAT
void sign_compat_exception_context_asm(void *regs);
void auth_compat_exception_context_asm(void *regs);

int set_compat_exception_context_register_asm(void *regs, int offset, u64 val);
#else
static inline void sign_compat_exception_context_asm(void *regs)
{
}

static inline void auth_compat_exception_context_asm(void *regs)
{
}

static inline int set_compat_exception_context_register_asm(void *regs, int offset, u64 val)
{
	return 0;
}
#endif

static inline void sign_compat_exception_context_unsafe(void *regs)
{
	return sign_compat_exception_context_asm(regs);
}

static inline void auth_compat_exception_context_unsafe(void *regs)
{
	return auth_compat_exception_context_asm(regs);
}

static inline void sign_exception_context_unsafe(void *regs)
{
	if (compat_user_mode((struct pt_regs *)regs)) {
		sign_compat_exception_context_asm(regs);
	} else {
		sign_exception_context_asm(regs);
	}
}

static inline void auth_exception_context_unsafe(void *regs)
{
	if (compat_user_mode((struct pt_regs *)regs)) {
		auth_compat_exception_context_asm(regs);
	} else {
		auth_exception_context_asm(regs);
	}
}

#define resign_compat_exception_context_start(regs)		\
do {								\
	unsigned long irq_flags;				\
	local_irq_save(irq_flags);				\
	auth_compat_exception_context_asm(regs);

#define resign_compat_exception_context_end(regs)		\
	sign_compat_exception_context_asm(regs);		\
	local_irq_restore(irq_flags);				\
} while (0)

#define resign_exception_context_start(regs)			\
do {								\
	unsigned long irq_flags;				\
	local_irq_save(irq_flags);				\
	auth_exception_context_unsafe(regs);

#define resign_exception_context_end(regs)			\
	sign_exception_context_unsafe(regs);				\
	local_irq_restore(irq_flags);				\
} while (0)

#define sign_exception_context_start(regs)			\
do {								\
	unsigned long irq_flags;				\
	local_irq_save(irq_flags);

#define sign_exception_context_end(regs)			\
	sign_exception_context_unsafe(regs);				\
	local_irq_restore(irq_flags);				\
} while (0)

void sign_compat_exception_context(void *regs);
void auth_compat_exception_context(void *regs);
void sign_exception_context(void *regs);
void auth_exception_context(void *regs);

int set_compat_exception_context_register(void *regs, enum pac_pt_regs regs_enum, u64 val);
void set_compat_exception_context_register_index(struct pt_regs *regs, int index, u64 val);
int set_exception_context_register(void *regs, enum pac_pt_regs regs_enum, u64 val);
void set_exception_context_register_index(struct pt_regs *regs, int index, u64 val);

#endif /* __POINTER_AUTH_CONTEXT_H */

