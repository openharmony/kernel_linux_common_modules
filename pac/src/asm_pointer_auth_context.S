// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 */

#include "asm/asm_pointer_auth_context.h"

#include <asm/asm-offsets.h>
#include <asm/sysreg.h>
#include <linux/linkage.h>

#ifdef CONFIG_COMPAT
	/* Obtain the regs of compat task to sign or authenticate. */
	.macro ldr_compat_pt_regs
	mov	x1, #0
	mov	x2, #0
	/* load lr, sp, pc, pstate of compat task */
	ldr	x3, [x0, #S_COMPAT_LR]
	ldr	x4, [x0, #S_COMPAT_SP]
	ldr	x5, [x0, #S_PC]
	ldr	x6, [x0, #S_PSTATE]
	.endm
#endif

	/* Obtain the regs of task to sign or authenticate. */
	.macro ldr_pt_regs
	/* load x16, x17, lr, sp, pc, pstate of task */
	ldp	x1, x2, [x0, #S_X16]
	ldr	x3, [x0, #S_LR]
	ldr	x4, [x0, #S_SP]
	ldr	x5, [x0, #S_PC]
	ldr	x6, [x0, #S_PSTATE]
	.endm

/*
 * Register sign_thread_context for AArch64.
 * void sign_thread_context(struct cpu_context *cpu_context)
 * On entry:
 *   x0: the pointer of cpu_context
 */
SYM_FUNC_START(sign_thread_context)
	mrs	x9, daif
	msr	daifset, #0x2
	ldr	x1, [x0, #CPU_CONTEXT_PC]
	ldr	x2, [x0, #CPU_CONTEXT_SP]
	sign_thread_context_common
	msr	daif, x9
	ret
SYM_FUNC_END(sign_thread_context)

/*
 * Register auth_thread_context for AArch64.
 * void auth_thread_context(struct cpu_context *cpu_context)
 * On entry:
 *   x0: the pointer of cpu_context
 */
SYM_FUNC_START(auth_thread_context)
	stp	x29, x30, [sp, #-16]!
	mov	x29, sp
	mrs	x9, daif
	msr	daifset, #0x2
	ldr	x1, [x0, #CPU_CONTEXT_PC]
	ldr	x2, [x0, #CPU_CONTEXT_SP]
	auth_thread_context_common
	msr	daif, x9
	ldp	x29, x30, [sp], #16
	ret
SYM_FUNC_END(auth_thread_context)

/*
 * Register set_exception_context_register_asm for AArch64.
 * int set_exception_context_register_asm(struct pt_regs *regs, int offset, u64 val);
 * On entry:
 *   x0: the regs of task
 *   x1: the offset of member in pt_regs struct
 *   x2: the value need to be update
 */
SYM_FUNC_START(set_exception_context_register_asm)
	stp	x29, x30, [sp, #-16]!
	mov	x29, sp
	mov	x9, x1
	mov	x10, x2
	mrs	x11, daif
	msr	daifset, #0x2
	ldr_pt_regs
	mov	x12, x1
	mov	x13, x2
	auth_exception_context_common x0, x12, x13
	cmp	x9, #S_LR
	b.eq	.Lupdate_lr
	b.ls	.Lchoose_lower
	cmp	x9, #S_PC
	b.eq	.Lupdate_pc
	b.cc	.Lupdate_sp
	cmp	x9, #S_PSTATE
	b.eq	.Lupdate_pstate
.Lerror_return:
	/* invalid value: return -EINVAL */
	mov	x0, #-22
	b	.Lreturn
.Lchoose_lower:
	cmp	x9, #S_X16
	b.eq	.Lupdate_x16
	b.hi	.Lupdate_x17
	b	.Lerror_return
.Lupdate_pstate:
	mov	x6, x10
.Lupdate_done:
	str	x10, [x0, x9]
	sign_exception_context_common
.Lreturn:
	mov	x0, #0
	msr	daif, x11
	ldp	x29, x30, [sp], #16
	ret

.Lupdate_x16:
	mov	x1, x10
	b		.Lupdate_done
.Lupdate_x17:
	mov	x2, x10
	b		.Lupdate_done
.Lupdate_lr:
	mov	x3, x10
	b		.Lupdate_done
.Lupdate_sp:
	mov	x4, x10
	b		.Lupdate_done
.Lupdate_pc:
	mov	x5, x10
	b		.Lupdate_done
SYM_FUNC_END(set_exception_context_register_asm)

#ifdef CONFIG_COMPAT
/*
 * Register set_compat_exception_context_register_asm for AArch64.
 * int set_compat_exception_context_register_asm(struct pt_regs *regs, int offset, u64 val);
 * On entry:
 *   x0: the regs of compat task
 *   x1: the offset of member in pt_regs struct
 *   x2: the value need to be update
 */
SYM_FUNC_START(set_compat_exception_context_register_asm)
	stp	x29, x30, [sp, #-16]!
	mov	x29, sp
	mov	x9, x1
	mov	x10, x2
	mrs	x11, daif
	msr	daifset, #0x2
	ldr_compat_pt_regs
	mov	x12, x1
	mov	x13, x2
	auth_exception_context_common x0, x12, x13
	cmp	x9, #S_COMPAT_LR
	b.eq	.Lupdate_compat_lr
	b.ls	.Lcompat_choose_lower
	cmp	x9, #S_PSTATE
	b.eq	.Lupdate_compat_pstate
	b.cc	.Lupdate_compat_pc
.Lcompat_error_return:
	/* invalid value: return -EINVAL */
	mov	x0, #-22
	b	.Lcompat_return
.Lcompat_choose_lower:
	cmp	x9, #S_COMPAT_SP
	b.eq	.Lupdate_compat_sp
	b	.Lcompat_error_return
.Lupdate_compat_pstate:
	mov	x6, x10
.Lcompat_update_done:
	str	x10, [x0, x9]
	sign_exception_context_common
.Lcompat_return:
	mov	x0, #0
	msr	daif, x11
	ldp	x29, x30, [sp], #16
	ret

.Lupdate_compat_lr:
	mov	x3, x10
	b		.Lcompat_update_done
.Lupdate_compat_sp:
	mov	x4, x10
	b		.Lcompat_update_done
.Lupdate_compat_pc:
	mov	x5, x10
	b		.Lcompat_update_done
SYM_FUNC_END(set_compat_exception_context_register_asm)
#endif

/*
 * Register sign_exception_context_asm for AArch64.
 * void sign_exception_context_asm(struct pt_regs *regs);
 * On entry:
 *   x0: the regs of task
 */
SYM_FUNC_START(sign_exception_context_asm)
	ldr_pt_regs
	sign_exception_context_common
	ret
SYM_FUNC_END(sign_exception_context_asm)

/*
 * Register auth_exception_context_asm for AArch64.
 * void auth_exception_context_asm(struct pt_regs *regs);
 * On entry:
 *   x0: the regs of task
 */
SYM_FUNC_START(auth_exception_context_asm)
	stp	x29, x30, [sp, #-16]!
	mov	x29, sp
	ldr_pt_regs
	auth_exception_context_common
	ldp	x29, x30, [sp], #16
	ret
SYM_FUNC_END(auth_exception_context_asm)

#ifdef CONFIG_COMPAT
/*
 * Register sign_compat_exception_context_asm for AArch64.
 * void sign_compat_exception_context_asm(struct pt_regs *regs);
 * On entry:
 *   x0: the regs of compat task
 */
SYM_FUNC_START(sign_compat_exception_context_asm)
	ldr_compat_pt_regs
	sign_exception_context_common
	ret
SYM_FUNC_END(sign_compat_exception_context_asm)

/*
 * Register auth_compat_exception_context_asm for AArch64.
 * void auth_compat_exception_context_asm(struct pt_regs *regs);
 * On entry:
 *   x0: the regs of compat task
 */
SYM_FUNC_START(auth_compat_exception_context_asm)
	stp	x29, x30, [sp, #-16]!
	mov	x29, sp
	ldr_compat_pt_regs
	auth_exception_context_common
	ldp	x29, x30, [sp], #16
	ret
SYM_FUNC_END(auth_compat_exception_context_asm)
#endif

