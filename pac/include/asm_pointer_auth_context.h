// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 */

#ifndef __ASM_POINTER_AUTH_CONTEXT_H
#define __ASM_POINTER_AUTH_CONTEXT_H

#include <asm/asm-offsets.h>
#include <asm/sysreg.h>

	/* Compute and store hash value of cpu context. */
	.macro sign_thread_context_common, tmp1=x0, tmp2=x1, tmp3=x2
	pacga	\tmp2, \tmp1, \tmp2
	pacga	\tmp2, \tmp3, \tmp2
	str	\tmp2, [\tmp1, CPU_CONTEXT_PAC_HASH]
	.endm

	/* Compute and auth hash value of cpu context. */
	.macro auth_thread_context_common, tmp1=x0, tmp2=x1, tmp3=x2
	pacga	\tmp2, \tmp1, \tmp2
	pacga	\tmp2, \tmp3, \tmp2
	ldr	\tmp3, [\tmp1, CPU_CONTEXT_PAC_HASH]
	cmp	\tmp2, \tmp3
	b.ne	.Lthread_context_pac_panic\@
	b	.Lauth_thread_context_done\@
.Lthread_context_pac_panic\@:
	adrp	x0, .Lthread_context_pac_str
	add	x0, x0, :lo12:.Lthread_context_pac_str
	bl	panic
.Lauth_thread_context_done\@:
	.endm

	/* Compute and store hash value of the regs. */
	.macro sign_exception_context_common, tmp1=x0, tmp2=x1, tmp3=x2, tmp4=x3, tmp5=x4, tmp6=x5, tmp7=x6
	pacga	\tmp2, \tmp1, \tmp2
	pacga	\tmp2, \tmp3, \tmp2
	pacga	\tmp2, \tmp4, \tmp2
	pacga	\tmp2, \tmp5, \tmp2
	pacga	\tmp2, \tmp6, \tmp2
	pacga	\tmp2, \tmp7, \tmp2
	str	\tmp2, [\tmp1, S_PAC_HASH]
	.endm

	/* Compute and auth hash value of the regs. */
	.macro auth_exception_context_common, tmp1=x0, tmp2=x1, tmp3=x2, tmp4=x3, tmp5=x4, tmp6=x5, tmp7=x6
	pacga	\tmp2, \tmp1, \tmp2
	pacga	\tmp2, \tmp3, \tmp2
	pacga	\tmp2, \tmp4, \tmp2
	pacga	\tmp2, \tmp5, \tmp2
	pacga	\tmp2, \tmp6, \tmp2
	pacga	\tmp2, \tmp7, \tmp2
	ldr	\tmp3, [\tmp1, S_PAC_HASH]
	cmp	\tmp2, \tmp3
	b.ne	.Lpt_regs_pac_panic\@
	b	.Lauth_exception_context_done\@
.Lpt_regs_pac_panic\@:
	adrp	x0, .Lpt_regs_pac_panic_str
	add	x0, x0, :lo12:.Lpt_regs_pac_panic_str
	bl	panic
.Lauth_exception_context_done\@:
	.endm

.Lpt_regs_pac_panic_str:
	.asciz	"Failed to match pac hash of exception context!\n"
	.align 2

.Lthread_context_pac_str:
	.asciz	"Failed to match pac hash of cpu context!\n"
	.align 2

	.macro pac_cpu_context sign_or_auth
	.if	\sign_or_auth == 0
	/* x0: base of curr task */
	mov	x2, x0
	.else
	/* x1: base of next task */
	mov	x2, x1
	.endif
	add	x2, x2, #THREAD_CPU_CONTEXT
	/* sign sp, lr of cpu context. */
	mov	x3, lr
	mov	x4, x9
	.if	\sign_or_auth == 0
	sign_thread_context_common x2, x3, x4
	.else
	auth_thread_context_common x2, x3, x4
	.endif
	.endm

	.macro sign_cpu_context sign=0
	pac_cpu_context \sign
	.endm

	.macro auth_cpu_context auth=1
	pac_cpu_context \auth
	.endm

	.macro prepare_compat_pt_regs, sign_or_auth
	/* base of pt_regs */
	mov	x23, sp
	mov	x24, #0
	mov	x25, #0
	/* sign lr, sp, pc, pstate of compat task */
	mov	x26, x14
	mov	x27, x13
	mrs	x20, elr_el1
	.if	\sign_or_auth == 0
	mrs	x21, spsr_el1
	.else
	mov	x21, x22
	.endif
	.endm

	.macro prepare_pt_regs, el, sign_or_auth
	/* base of pt_regs */
	mov	x23, sp
	/* sign x16, x17, lr, sp, pc, pstate of task */
	mov	x24, x16
	mov	x25, x17
	.if	\sign_or_auth == 0
	mov	x26, lr
	.else
	ldr	x26, [x23, #S_LR]
	.endif
	.if	\el == 0
	mrs	x27, sp_el0
	.else
	add	x27, x23, #S_FRAME_SIZE
	.endif
	mrs	x20, elr_el1
	.if	\sign_or_auth == 0
	mrs	x21, spsr_el1
	.else
	mov	x21, x22
	.endif
	.endm

	.macro pac_pt_regs, el, sign_or_auth
	.if	\el == 0
	/* Test the task is in the mode of 32-bit or 64-bit */
	mrs	x23, spsr_el1
	mov	x24, #(PSR_MODE32_BIT | PSR_MODE_MASK)
	mov	x25, #(PSR_MODE32_BIT | PSR_MODE_EL0t)
	and	x23, x23, x24
	sub	x23, x23, x25
	cbnz	x23, .Lis_not_compat_task\@
	/* Task in 32-bit mode */
	prepare_compat_pt_regs \sign_or_auth
	b	.Lpac_handle\@
	.endif
	/* Task in 64-bit mode */
.Lis_not_compat_task\@:
	prepare_pt_regs \el, \sign_or_auth
	/* Call the sign or auth function. */
.Lpac_handle\@:
	.if	\sign_or_auth == 0
	sign_exception_context_common x23, x24, x25, x26, x27, x20, x21
	.else
	auth_exception_context_common x23, x24, x25, x26, x27, x20, x21
	.endif
	.endm

	.macro sign_pt_regs, el, sign=0
	pac_pt_regs \el, \sign
	.endm

	.macro auth_pt_regs, el, auth=1
	pac_pt_regs \el, \auth
	.endm

#endif /* __ASM_POINTER_AUTH_CONTEXT_H */
