// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 */

#include <linux/mm.h>
#include <linux/rmap.h>
#include <linux/mman.h>
#include <linux/fs.h>
#include <linux/xpm.h>
#include <linux/dcache.h>
#ifdef CONFIG_HW_KERNEL_SG
#include <security/security_guard_collect.h>
#endif
#include "xpm_log.h"
#include "xpm_report.h"

#ifndef CONFIG_HW_KERNEL_SG
typedef struct {
	unsigned long event_id;
	unsigned int version;
	unsigned int content_len;
	char content[0];
} event_info;

unsigned int report_security_info(const event_info *event)
{
	xpm_log_info("%d: %s", event->event_id, event->content);
	return 0;
}
#endif

static char *xpm_get_filename(struct xpm_event_param *param, char *buf, int len)
{
	char *filename = NULL;
	struct file *file = NULL;

	if (param->file)
		file = param->file;
	else if (param->vma && param->vma->vm_file)
		file = param->vma->vm_file;
	else
		return NULL;

	filename = d_absolute_path(&file->f_path, buf, len);
	if (IS_ERR(filename)) {
		xpm_log_error("xpm get absolute path failed");
		return NULL;
	}

	return filename;
}

static int set_init_content(struct xpm_event_param *param,
	uint8_t *content, uint32_t content_len)
{
	int len;

	len = snprintf(content, content_len,
		"{ "JSTR_PAIR(event_type, %s)", "JVAL_PAIR(timestamp, %llu)" }",
		param->event_type, param->timestamp);

	if (len < 0 || len > content_len) {
		xpm_log_error("snprintf init content failed");
		return -EINVAL;
	}

	return 0;
}

#define PROT_MASK (PROT_EXEC | PROT_READ | PROT_WRITE)
const static char *code_type[] = {
	[TYPE_ABC] = "ABC",
	[TYPE_ELF] = "ELF",
	[TYPE_ANON] = "ANON"
};
static int set_mmap_content(struct xpm_event_param *param, uint8_t *content,
	uint32_t content_len)
{
	int len;

	if (!param->vma) {
		xpm_log_error("input vma is NULL");
		return -EINVAL;
	}

	len = snprintf(content, content_len,
		"{ "JSTR_PAIR(event_type, %s)", "JVAL_PAIR(timestamp, %llu)", "
		JVAL_PAIR(pid, %u)", "JSTR_PAIR(filename, %s)", "
		JSTR_PAIR(code_type, %s)", "JVAL_PAIR(prot, %lu)","
		JVAL_PAIR(pgoff, %lu)", "JVAL_PAIR(size, %lu)" }",
		param->event_type, param->timestamp, param->pid,
		param->filename ? param->filename : "",
		code_type[param->code], param->prot & PROT_MASK,
		param->vma->vm_pgoff,
		param->vma->vm_end - param->vma->vm_start);

	if (len < 0 || len > content_len) {
		xpm_log_error("snprintf code mmap content failed");
		return -EINVAL;
	}

	return 0;
}

static int set_file_content(struct xpm_event_param *param,
	uint8_t *content, uint32_t content_len)
{
	int len;

	len = snprintf(content, content_len,
		"{ "JSTR_PAIR(event_type, %s)", "JVAL_PAIR(timestamp, %llu)", "
		JVAL_PAIR(pid, %u)", "JSTR_PAIR(filename, %s)" }",
		param->event_type, param->timestamp, param->pid,
		param->filename ? param->filename : "");

	if (len < 0 || len > content_len) {
		xpm_log_error("snprintf file format content failed");
		return -EINVAL;
	}

	return 0;
}

static int set_integrity_content(struct xpm_event_param *param,
	uint8_t *content, uint32_t content_len)
{
	int len;
	char *page_type;

	if (!param->vma || !param->page) {
		xpm_log_error("input vma or page is NULL");
		return -EINVAL;
	}

	page_type = PageKsm(param->page) ?
		"[ksm]" : PageAnon(param->page) ? "[anon]" : "[file]";

	len = snprintf(content, content_len,
		"{ " JSTR_PAIR(event_type, %s)", "JVAL_PAIR(timestamp, %llu)", "
		JVAL_PAIR(pid, %u)","JSTR_PAIR(page_type, %s)", "
		JSTR_PAIR(filename, %s)", "JVAL_PAIR(page_index, %lu)","
		JVAL_PAIR(page_prot, %lu)" }",
		param->event_type, param->timestamp, param->pid, page_type,
		param->filename ? param->filename : "", param->page->index,
		param->vma->vm_page_prot.pgprot & PROT_MASK);

	if (len < 0 || len > content_len) {
		xpm_log_error("snprintf init integrity failed");
		return -EINVAL;
	}

	return 0;
}

static const struct xpm_event_info xpm_event[] = {
	[TYPE_DEVICEFS_UNINIT] = { "devicefs uninitialized",
		EVENT_INIT, set_init_content },
	[TYPE_DEBUGFS_UNINIT] = { "debugfs uninitialized",
		EVENT_INIT, set_init_content },
	[TYPE_DM_DISABLE] = { "dm-verity disable",
		EVENT_INIT, set_init_content },
	[TYPE_FORMAT_UNDEF] = { "unkown file format",
		EVENT_FILE, set_file_content },
	[TYPE_ANON_EXEC] = { "anon executed",
		EVENT_MMAP, set_file_content },
	[TYPE_SIGN_INVALID] = { "invalid signature",
		EVENT_MMAP, set_mmap_content },
	[TYPE_DATA_MMAP_CODE] = { "data mmap code",
		EVENT_MMAP, set_mmap_content },
	[TYPE_INTEGRITY_RO] = { "code tampered",
		EVENT_INTEGRITY, set_integrity_content },
	[TYPE_INTEGRITY_WT] = { "data executed",
		EVENT_INTEGRITY, set_integrity_content },
};

static int report_event_inner(enum xpm_event_type type,
	struct xpm_event_param *param, event_info *event)
{
	int ret;

	ret = xpm_event[type].set_content(param, event->content,
		MAX_CONTENT_LEN);
	if (ret) {
		xpm_log_error("type [%d] set content failed", type);
		return ret;
	}
	event->content_len = strlen(event->content);
	event->event_id = xpm_event[type].event_id;
	event->version = XPM_EVENT_VERSION;

	ret = report_security_info(event);
	if (ret) {
		xpm_log_error("type [%d] report security info failed", type);
		return ret;
	}

	return 0;
}

static int xpm_report_event(enum xpm_event_type type,
	struct xpm_event_param *param)
{
	int ret;
	event_info *sg_event;
	char *buf;

	if (!(xpm_event[type].set_content)) {
		xpm_log_error("type [%d] set content func invalid", type);
		return -EINVAL;
	}

	sg_event = kzalloc(sizeof(event_info) + MAX_CONTENT_LEN, GFP_KERNEL);
	if (!sg_event) {
		xpm_log_error("alloc security guard event failed");
		return -ENOMEM;
	}

	buf = __getname();
	if (!buf) {
		xpm_log_error("alloc file name buf failed");
		kfree(sg_event);
		return -ENOMEM;
	}

	param->event_type = xpm_event[type].event_type;
	param->filename = xpm_get_filename(param, buf, PATH_MAX);
	param->timestamp = ktime_get_real_seconds();
	param->pid = current->pid;

	ret = report_event_inner(type, param, sg_event);

	__putname(buf);
	kfree(sg_event);
	return ret;
}

void report_init_event(enum xpm_event_type type)
{
	struct xpm_event_param param = {0};

	xpm_report_ratelimited(xpm_report_event, type, &param);
}

void report_file_event(enum xpm_event_type type, struct file *file)
{
	struct xpm_event_param param = {0};

	param.file = file;
	xpm_report_ratelimited(xpm_report_event, type, &param);
}

void report_mmap_event(enum xpm_event_type type, struct vm_area_struct *vma,
	int code, int prot)
{
	struct xpm_event_param param = {0};

	param.vma = vma;
	param.code = code;
	param.prot = prot;
	xpm_report_ratelimited(xpm_report_event, type, &param);
}

void report_integrity_event(enum xpm_event_type type,
	struct vm_area_struct *vma, struct page *page)
{
	struct xpm_event_param param = {0};

	param.vma = vma;
	param.page = page;
	xpm_report_ratelimited(xpm_report_event, type, &param);
}
