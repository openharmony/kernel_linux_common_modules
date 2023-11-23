// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 */

#include "ced_detection.h"
#include "ced_log.h"

void switch_task_namespaces_permission_hook(const struct nsproxy *new, int *ret)
{
	*ret = 0;
	if (new == NULL)
		return;

	if (ced_has_check_perm()) {
		*ret = -EPERM;
		ced_log_error("switch task namespace is not permitted in container process");
		return;
	}
}