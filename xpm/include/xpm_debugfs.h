/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 */

#ifndef _XPM_DEBUGFS_H

#ifdef CONFIG_SECURITY_XPM_DEBUG
int xpm_debugfs_init(void);
void xpm_debugfs_exit(void);
bool xpm_is_permissve_mode(void);

#else
static inline int xpm_debugfs_init(void)
{
	return 0;
}

static inline void xpm_debugfs_exit(void)
{
}

static inline bool xpm_is_permissve_mode(void)
{
	return true;
}
#endif

#endif /* _XPM_DEBUGFS_H */
