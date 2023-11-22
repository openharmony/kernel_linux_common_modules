// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 */

#include "xpm_common.h"

bool xpm_is_anonymous_vma(struct vm_area_struct *vma)
{
	return vma_is_anonymous(vma) || vma_is_shmem(vma);
}
