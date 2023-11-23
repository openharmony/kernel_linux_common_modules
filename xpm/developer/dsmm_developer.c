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
static uint32_t developer_state = STATE_UNINT;

static uint32_t g_state_table[BUILD_VARIANT_MAX][CMDLINE_DEV_STATE_MAX] = {
	{ STATE_OFF, STATE_ON, STATE_OFF },
	{ STATE_ON, STATE_ON, STATE_ON },
};

static int get_developer_status(uint32_t *status)
{
	if (!strstr(saved_command_line, "developer_mode=")) {
		*status = CMDLINE_DEV_STATE_NA;
	} else if (strstr(saved_command_line, "developer_mode=1")) {
		*status = CMDLINE_DEV_STATE_ON;
	} else if (strstr(saved_command_line, "developer_mode=0")) {
		*status = CMDLINE_DEV_STATE_OFF;
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

int get_developer_mode_state(void)
{
	uint32_t variant, status;

	if (developer_state != STATE_UNINT)
		return developer_state;

#ifdef CONFIG_DSMM_DEVELOPER_ENABLE
	if (get_build_variant(&variant) || get_developer_status(&status)) {
		xpm_log_error("get build variant or developer status failed");
		developer_state = STATE_OFF;
	} else {
		developer_state = g_state_table[variant][status];
	}
#else
	developer_state = STATE_ON;
#endif

	return developer_state;
}

#define PROC_DEVELOPER_LEN 50
static ssize_t dsmm_read_developer_proc(struct file *file, char __user *buf,
	size_t count, loff_t *pos)
{
	size_t len;
	uint32_t state;
	char proc_developer[PROC_DEVELOPER_LEN] = {0};

	state = get_developer_mode_state();
	len = snprintf(proc_developer, PROC_DEVELOPER_LEN - 1,
		DSMM_DEVELOPER_PARAM_NAME"=%s",
		state == STATE_ON ? "true" : "false");

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
