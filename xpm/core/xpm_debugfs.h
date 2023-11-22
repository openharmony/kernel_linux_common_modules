/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 */

#ifndef _XPM_DEBUGFS_H

#define XPM_PERMISSIVE_MODE 0
#define XPM_ENFORCE_MODE 1

#ifdef CONFIG_SECURITY_XPM_DEBUG
int xpm_debugfs_init(void);
void xpm_debugfs_exit(void);

/**
 * xpm_ret - Return value adapted to xpm enforce and permissive modes.
 *
 * @ret:    Return value.
 *
 * Returns ret on enforce mode, 0 on permissive mode.
 */
int xpm_ret(int ret);
#else
static inline int xpm_debugfs_init(void)
{
	return 0;
}

static inline void xpm_debugfs_exit(void)
{
}

static inline int xpm_ret(int ret)
{
	return XPM_PERMISSIVE_MODE;
}
#endif

#endif /* _XPM_DEBUGFS_H */
