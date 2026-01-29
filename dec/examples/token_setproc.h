// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 */

#ifndef _DEC_TOKEN_SETPROC_H
#define _DEC_TOKEN_SETPROC_H

#include <stdint.h>
#include "setproc_common.h"

uint64_t GetSelfTokenID(void);
int SetSelfTokenID(uint64_t tokenID);
uint64_t GetFirstCallerTokenID(void);
int SetFirstCallerTokenID(uint64_t tokenID);

#endif /* _DEC_TOKEN_SETPROC_H */