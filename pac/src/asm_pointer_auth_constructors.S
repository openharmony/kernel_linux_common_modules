// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 */

#include <linux/linkage.h>
#include <linux/init.h>
#include <asm/assembler.h>

.pushsection ".init.text", "ax"

SYM_CODE_START(init_constructors)
	mov	x21, x30
	adrp	x19, __ctors_end
	adrp	x20, __ctors_start
	add	x19, x19, #:lo12:__ctors_end
	add	x20, x20, #:lo12:__ctors_start
	cmp	x20, x19
	b.cs	4f
3:	ldr	x8, [x20], #8
	blr	x8
	cmp	x20, x19
	b.cc	3b
4:	mov	x30, x21
	ret
SYM_CODE_END(init_constructors)
