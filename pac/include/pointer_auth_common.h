// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 */

#ifndef __POINTER_AUTH_COMMON_H__
#define __POINTER_AUTH_COMMON_H__

#define is_addr_error(addr) (((addr) >> 48) ^ 0xffff)

#define pauth_sign(type, key, addr, mod) \
	pauth_common(pac, type, key, addr, mod)

#define pauth_validate(type, key, addr, mod) \
	pauth_common(aut, type, key, addr, mod)

#define pauth_strip(type, addr) \
({ \
	const void *__addr = (addr); \
\
	asm ("xpac" #type " %0\n" : "+r" (__addr)); \
	(typeof (addr))__addr; \
})

#define pauth_hash(addr, mod) ((unsigned int) (pauth_pacga(addr, mod) >> 32))

#define pauth_common(prefix, type, key, addr, mod) \
({ \
	const void *__addr = (addr); \
	unsigned long __mod = (unsigned long)(mod); \
\
	if (__builtin_constant_p(mod) && (__mod == 0)) \
		asm (#prefix #type "z" #key " %0\n" : "+r" (__addr)); \
	else \
		asm (#prefix #type #key " %0, %1\n" : "+r" (__addr) : \
			"r" (__mod)); \
	(typeof (addr))(__addr); \
})

#define pauth_get_raw_data(addr) \
({ \
	const void *__addr; \
	asm ("mov %0, %1\n" : "=&r" (__addr) : \
		"r" (addr)); \
	(void *)(__addr); \
})

#define pauth_sign_function(fun, mod, key) \
({ \
	const void *__fun = (fun); \
	unsigned long __mod = (unsigned long)(mod); \
	asm ("paci" #key " %0, %1\n" : "+r" (__fun) :   \
		"r" (__mod));  \
	(void *)(__fun); \
})

#define pauth_pacda(addr, mod)	pauth_common(pac, d, a, addr, mod)

#define pauth_pacdb(addr, mod)	pauth_common(pac, d, b, addr, mod)

#define pauth_pacia(addr, mod)	pauth_common(pac, i, a, addr, mod)

#define pauth_pacib(addr, mod)	pauth_common(pac, i, b, addr, mod)

#define pauth_pacga(addr, mod) \
({ \
	const void *__addr = (addr); \
	unsigned long __mod = (unsigned long)(mod); \
	unsigned long __pac; \
\
	asm ("pacga %0, %1, %2\n" : "=r" (__pac) : "r" (__addr), \
		"r" (__mod)); \
	__pac; \
})

#define pauth_autda(addr, mod)	pauth_common(aut, d, a, addr, mod)

#define pauth_autdb(addr, mod)	pauth_common(aut, d, b, addr, mod)

#define pauth_autia(addr, mod)	pauth_common(aut, i, a, addr, mod)

#define pauth_autib(addr, mod)	pauth_common(aut, i, b, addr, mod)

#define pauth_xpacd(addr)		pauth_strip(d, addr)

#define pauth_xpaci(addr)		pauth_strip(i, addr)

#endif /* __POINTER_AUTH_COMMON_H__ */
