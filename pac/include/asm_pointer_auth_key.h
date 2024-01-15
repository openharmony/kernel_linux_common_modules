/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 *
 * Pointer authentication keys initialisation.
 */

#ifndef __ASM_POINTER_AUTH_KEY_H
#define __ASM_POINTER_AUTH_KEY_H

#include <asm/alternative.h>
#include <asm/asm-offsets.h>
#include <asm/cpucaps.h>
#include <asm/sysreg.h>

	.macro __ptrauth_address_keys_install_kernel tmp1, tmp2, tmp3
	ldp	\tmp2, \tmp3, [\tmp1, #PTRAUTH_KERNEL_KEY_APIB]
	msr_s	SYS_APIBKEYLO_EL1, \tmp2
	msr_s	SYS_APIBKEYHI_EL1, \tmp3

	adr_l	\tmp1, kernel_common_keys
	ldp	\tmp2, \tmp3, [\tmp1, #PTRAUTH_KERNEL_KEY_APIA]
	msr_s	SYS_APIAKEYLO_EL1, \tmp2
	msr_s	SYS_APIAKEYHI_EL1, \tmp3

	ldp	\tmp2, \tmp3, [\tmp1, #PTRAUTH_KERNEL_KEY_APDA]
	msr_s	SYS_APDAKEYLO_EL1, \tmp2
	msr_s	SYS_APDAKEYHI_EL1, \tmp3

	ldp	\tmp2, \tmp3, [\tmp1, #PTRAUTH_KERNEL_KEY_APDB]
	msr_s	SYS_APDBKEYLO_EL1, \tmp2
	msr_s	SYS_APDBKEYHI_EL1, \tmp3
	.endm

	.macro __ptrauth_generic_key_install_kernel tmp1, tmp2, tmp3
	ldp	\tmp2, \tmp3, [\tmp1, #PTRAUTH_KERNEL_KEY_APGA]
	msr_s	SYS_APGAKEYLO_EL1, \tmp2
	msr_s	SYS_APGAKEYHI_EL1, \tmp3
	.endm

	.macro ptrauth_keys_install_kernel_all tsk, tmp1, tmp2, tmp3
	mov	\tmp1, #THREAD_KEYS_KERNEL
	add	\tmp1, \tsk, \tmp1

alternative_if_not ARM64_HAS_ADDRESS_AUTH
	b	.Lno_addr_auth\@
alternative_else_nop_endif
	__ptrauth_address_keys_install_kernel \tmp1, \tmp2, \tmp3

.Lno_addr_auth\@:
alternative_if ARM64_HAS_GENERIC_AUTH
	__ptrauth_generic_key_install_kernel \tmp1, \tmp2, \tmp3
alternative_else_nop_endif
	isb
	.endm

	.macro __ptrauth_keys_install_kernel_all tsk, tmp1, tmp2, tmp3
	mov	\tmp1, #THREAD_KEYS_KERNEL
	add	\tmp1, \tsk, \tmp1
	__ptrauth_address_keys_install_kernel \tmp1, \tmp2, \tmp3
	__ptrauth_generic_key_install_kernel \tmp1, \tmp2, \tmp3
	.endm

#endif
