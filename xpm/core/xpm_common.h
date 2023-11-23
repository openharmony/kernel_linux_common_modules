/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 */

#ifndef _XPM_COMMON_H
#define _XPM_COMMON_H

#include <linux/mm.h>
#include <linux/sched.h>

/**
 * xpm_is_anonymous_vma - Determine whether vma is anonymous.
 *
 * @vma:    Pointer to "struct vm_area_struct" which need to be determined.
 *
 * Returns true on anonymunt, 0 on permissive mode.
 *
 * NOTE: shemem also been treated as anonymous vma.
 */
bool xpm_is_anonymous_vma(struct vm_area_struct *vma);

#endif /* _XPM_COMMON_H */
