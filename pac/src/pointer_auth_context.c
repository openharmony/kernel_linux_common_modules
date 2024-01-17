// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 */

#include <asm/asm-offsets.h>
#include <asm/ptrace.h>
#include <linux/irqflags.h>

/* The members of arrays below are corresponding to the enum defined in pointer_auth_context.h:
 * enum pac_pt_regs {
 *   REGS_X16 = 0,
 *   REGS_X17,
 *   REGS_LR,
 *   REGS_SP,
 *   REGS_PC,
 *   REGS_PSTATE,
 * };
 *
 * compat_regs_offset_array[]:
 *   S_X14: the offset of compat_lr
 *   S_X13: the offset of compat_sp
 */
static off_t compat_regs_offset_array[] = {0, 0, S_X14, S_X13, S_PC, S_PSTATE};
static off_t regs_offset_array[] = {S_X16, S_X17, S_LR, S_SP, S_PC, S_PSTATE};

int set_compat_exception_context_register(void *regs, enum pac_pt_regs regs_enum, u64 val)
{
	switch (regs_enum) {
	case REGS_LR:
	case REGS_SP:
	case REGS_PC:
	case REGS_PSTATE:
		return set_compat_exception_context_register_asm(regs, compat_regs_offset_array[regs_enum], val);
	default:
		return -EINVAL;
	}
}

int set_exception_context_register(void *regs, enum pac_pt_regs regs_enum, u64 val)
{
	if (compat_user_mode((struct pt_regs *)regs)) {
		return set_compat_exception_context_register(regs, regs_enum, val);
	} else {
		switch (regs_enum) {
		case REGS_X16:
		case REGS_X17:
		case REGS_LR:
		case REGS_SP:
		case REGS_PC:
		case REGS_PSTATE:
			return set_exception_context_register_asm(regs, regs_offset_array[regs_enum], val);
		default:
			return -EINVAL;
		}
	}
}

void set_compat_exception_context_register_index(struct pt_regs *regs, int index, uint64_t val)
{
	/* 14 means the index of compat_lr */
	if (index == 14) {
		set_compat_exception_context_register_asm(regs, S_X14, val);
	/* 13 means the index of compat_sp */
	} else if (index == 13) {
		set_compat_exception_context_register_asm(regs, S_X13, val);
	} else {
		regs->regs[index] = val;
	}
}

void set_exception_context_register_index(struct pt_regs *regs, int index, uint64_t val)
{
	off_t offset;

	if (compat_user_mode(regs)) {
		set_compat_exception_context_register_index(regs, index, val);
	} else {
		switch (index) {
		/* 16 means the index of regs[16] */
		case 16:
		/* 17 means the index of regs[17] */
		case 17:
		/* 30 means the index of regs[30] */
		case 30:
			offset = offsetof(struct pt_regs, regs[index]);
			set_exception_context_register_asm(regs, offset, val);
			break;
		default:
			regs->regs[index] = val;
		}
	}
}

void sign_compat_exception_context(void *regs)
{
	unsigned long irq_flags;
	local_irq_save(irq_flags);
	sign_compat_exception_context_asm(regs);
	local_irq_restore(irq_flags);
}

void auth_compat_exception_context(void *regs)
{
	unsigned long irq_flags;
	local_irq_save(irq_flags);
	auth_compat_exception_context_asm(regs);
	local_irq_restore(irq_flags);
}

void sign_exception_context(void *regs)
{
	unsigned long irq_flags;
	local_irq_save(irq_flags);
	if (compat_user_mode((struct pt_regs *)regs)) {
		sign_compat_exception_context_asm(regs);
	} else {
		sign_exception_context_asm(regs);
	}
	local_irq_restore(irq_flags);
}

void auth_exception_context(void *regs)
{
	unsigned long irq_flags;
	local_irq_save(irq_flags);
	if (compat_user_mode((struct pt_regs *)regs)) {
		auth_compat_exception_context_asm(regs);
	} else {
		auth_exception_context_asm(regs);
	}
	local_irq_restore(irq_flags);
}
