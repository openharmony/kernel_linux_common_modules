// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 */

#include <linux/proc_fs.h>
#include "dsmm_developer.h"
#include "xpm_log.h"

#define DSMM_DIR "dsmm"
#define DSMM_DEVELOPER_FILE "developer"
#define DSMM_DEVELOPER_PARAM_NAME "const.security.developermode.state"

static struct proc_dir_entry *g_dsmm_dir;

static const char *g_developer_status[BUILD_VARIANT_MAX][DEVELOPER_PROC_STATUS_MAX] = {
	{ DEVELOPER_STATUS_OFF, DEVELOPER_STATUS_ON, DEVELOPER_STATUS_OFF },
	{ DEVELOPER_STATUS_ON, DEVELOPER_STATUS_ON, DEVELOPER_STATUS_OFF },
};

static int get_developer_status(uint32_t *status)
{
	if (!strstr(saved_command_line, "developer_mode=")) {
		*status = DEVELOPER_PROC_STATUS_NA;
	} else if (strstr(saved_command_line, "developer_mode=1")) {
		*status = DEVELOPER_PROC_STATUS_ON;
	} else if (strstr(saved_command_line, "developer_mode=0")) {
		*status = DEVELOPER_PROC_STATUS_OFF;
	} else {
		xpm_log_error("invalid developer_mode value in cmdline");
		return -EINVAL;
	}

	return 0;
}

static int get_build_variant(uint32_t *variant)
{
	if (strstr(saved_command_line, "buildvariant=user")) {
		*variant = BUILD_VARIANT_USER;
	} else if (strstr(saved_command_line, "buildvariant=eng")) {
		*variant = BUILD_VARIANT_ENG;
	} else {
		xpm_log_error("invalid buildvariant value in cmdline");
		return -EINVAL;
	}

	return 0;
}

const char *developer_mode_state(void)
{
	uint32_t variant, status;

#ifdef CONFIG_DSMM_DEVELOPER_ENABLE
	if (get_build_variant(&variant) || get_developer_status(&status)) {
		xpm_log_error("get build variant or developer status failed");
		return NULL;
	}

	return g_developer_status[variant][status];
#else
	return DEVELOPER_STATUS_ON;
#endif
}

#define PROC_DEVELOPER_LEN 50
static ssize_t dsmm_read_developer_proc(struct file *file, char __user *buf,
	size_t count, loff_t *pos)
{
	size_t len;
	char proc_developer[PROC_DEVELOPER_LEN] = {0};
	const char *developer_state = developer_mode_state();

	if (!developer_state) {
		xpm_log_error("developer mode state invalid");
		return 0;
	}

	len = snprintf(proc_developer, PROC_DEVELOPER_LEN - 1,
		DSMM_DEVELOPER_PARAM_NAME"=%s", developer_state);

	return simple_read_from_buffer(buf, count, pos, proc_developer, len);
}

static const struct proc_ops dsmm_proc_fops_developer = {
	.proc_read = dsmm_read_developer_proc,
};

void dsmm_developer_proc_create(void)
{
	g_dsmm_dir = proc_mkdir(DSMM_DIR, NULL);
	if (!g_dsmm_dir) {
		xpm_log_error("[%s] proc dir create failed", DSMM_DIR);
		return;
	}

	if(!proc_create(DSMM_DEVELOPER_FILE, S_IRUGO, g_dsmm_dir,
		&dsmm_proc_fops_developer)) {
		xpm_log_error("[%s] proc file create failed",
			DSMM_DEVELOPER_FILE);
	}
}

void dsmm_developer_proc_clean(void)
{
	if (!g_dsmm_dir)
		return;

	remove_proc_entry(DSMM_DEVELOPER_FILE, g_dsmm_dir);
	remove_proc_entry(DSMM_DIR, NULL);
}
