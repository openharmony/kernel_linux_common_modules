/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 *
 * Pointer authentication keys initialisation.
 */

#include <linux/linkage.h>
#include <linux/init.h>
#include <asm/assembler.h>

.pushsection ".init.text", "ax"

	.macro ptrauth_key_init type, tmp
	mrs	x25, ap\type\()keylo_el1
	str	x25, [\tmp]
	mrs	x25, ap\type\()keyhi_el1
	str	x25, [\tmp, #8]
	.endm

	/* init ptrauth key for kernel backward-edge CFI */
	.macro ptrauth_back_key_init
	mov	x6, x5				/* x5: address of init task */
	mov	x7, #THREAD_KEYS_KERNEL
	add	x6, x6, x7
	add	x6, x6, #PTRAUTH_KERNEL_KEY_APIB
	ptrauth_key_init ib, x6
	.endm

	/* init common ptrauth keys for kernel forward-edge CFI, data pointer DFI and data field DFI */
	.macro ptrauth_common_keys_init
	adr_l	x7, kernel_common_keys
	mov	x6, x7
	add	x6, x6, #PTRAUTH_KERNEL_KEY_APIA
	ptrauth_key_init ia, x6

	mov	x6, x7
	add	x6, x6, #PTRAUTH_KERNEL_KEY_APDA
	ptrauth_key_init da, x6

	mov	x6, x7
	add	x6, x6, #PTRAUTH_KERNEL_KEY_APDB
	ptrauth_key_init db, x6

	mov	x6, x7
	add	x6, x6, #PTRAUTH_KERNEL_KEY_APGA
	ptrauth_key_init ga, x6

	.endm

SYM_CODE_START(ptrauth_kernel_keys_init)
	ptrauth_back_key_init
	ptrauth_common_keys_init
	isb
	ret
SYM_CODE_END(ptrauth_kernel_keys_init)
