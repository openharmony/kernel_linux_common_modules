// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 */

#ifndef _VERIFY_CERT_CHAIN_H
#define _VERIFY_CERT_CHAIN_H

/*
 * verify_cert_chain.c
 */

void code_sign_verify_certchain(const void *raw_pkcs7, size_t pkcs7_len, int *ret);

#endif /* _VERIFY_CERT_CHAIN_H */
