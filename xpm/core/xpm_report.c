// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 */

#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/fsverity.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/rmap.h>
#include <linux/xpm.h>

#ifdef CONFIG_HW_KERNEL_SG
#include <security/security_guard_collect.h>
#endif

#include "code_sign_ext.h"
#include "fsverity_private.h"
#include "xpm_log.h"
#include "xpm_report.h"

#define PROT_MASK (PROT_EXEC | PROT_READ | PROT_WRITE)
static char *code_type_tbl[] = {
	[TYPE_ABC] = "ABC",
	[TYPE_ELF] = "ELF",
	[TYPE_ANON] = "ANON"
};

#ifndef CONFIG_HW_KERNEL_SG
typedef struct {
	unsigned long event_id;
	unsigned int version;
	unsigned int content_len;
	char content[0];
} event_info;
#endif

unsigned int xpm_report_security_info(const event_info *event)
{
	xpm_log_error("%d: %s", event->event_id, event->content);

#ifdef CONFIG_HW_KERNEL_SG
	return report_security_info(event);
#else
	return 0;
#endif
}

static void xpm_set_filename(struct file *file, struct xpm_report_info *info)
{
	char *filename = NULL;
	char *buffer = NULL;

	if (!file)
		return;

	buffer = kzalloc(sizeof(info->filename), GFP_ATOMIC);
	if (!buffer) {
		xpm_log_error("alloc filename buffer failed");
		return;
	}

	filename = file_path(file, buffer, sizeof(info->filename) - 1);
	if (IS_ERR(filename)) {
		xpm_log_error("xpm set file path failed");
	} else {
		strcpy(info->filename, filename);
	}

	kfree(buffer);
}

static int set_init_content(struct xpm_report_info *info,
	uint8_t *content, uint32_t content_len)
{
	int len;

	len = snprintf(content, content_len,
		"{ "JSTR_PAIR(event_type, %s)", "JVAL_PAIR(timestamp, %llu)" }",
		info->event_type, info->timestamp);

	if (len < 0 || len > content_len) {
		xpm_log_error("snprintf init content failed");
		return -EINVAL;
	}

	return 0;
}

static int set_mmap_content(struct xpm_report_info *info, uint8_t *content,
	uint32_t content_len)
{
	int len;

	len = snprintf(content, content_len,
		"{ "JSTR_PAIR(event_type, %s)", "JSTR_PAIR(code_type, %s)", "
		JVAL_PAIR(pid, %u)", "JSTR_PAIR(comm, %s)", "
		JSTR_PAIR(filename, %s)", "JVAL_PAIR(vm_prot, %lu)","
		JVAL_PAIR(vm_pgoff, %lu)", "JVAL_PAIR(vm_size, %lu)", "
		JVAL_PAIR(p_id_type, %u)", "JSTR_PAIR(p_ownerid, %u)", "
		JVAL_PAIR(f_id_type, %u)", "JSTR_PAIR(f_ownerid, %u)", "
		JSTR_PAIR(timestamp, %llu)" }",
		info->event_type, info->code_type, info->pid, info->comm,
		info->filename, info->vm_prot, info->vm_pgoff, info->vm_size,
		info->pcs_info.id_type, info->pcs_info.ownerid,
		info->fcs_info.id_type, info->fcs_info.ownerid,
		info->timestamp);

	if (len < 0 || len > content_len) {
		xpm_log_error("snprintf code mmap content failed");
		return -EINVAL;
	}

	return 0;
}

static int set_file_content(struct xpm_report_info *info,
	uint8_t *content, uint32_t content_len)
{
	int len;

	len = snprintf(content, content_len,
		"{ "JSTR_PAIR(event_type, %s)", "JVAL_PAIR(pid, %u)", "
		JSTR_PAIR(comm, %s)", "JSTR_PAIR(filename, %s)", "
		JVAL_PAIR(timestap, %llu)" }",
		info->event_type, info->pid, info->comm,
		info->filename, info->timestamp);

	if (len < 0 || len > content_len) {
		xpm_log_error("snprintf file format content failed");
		return -EINVAL;
	}

	return 0;
}

static int set_integrity_content(struct xpm_report_info *info,
	uint8_t *content, uint32_t content_len)
{
	int len;

	len = snprintf(content, content_len,
		"{ "JSTR_PAIR(event_type, %s)", "JVAL_PAIR(pid, %u)", "
		JSTR_PAIR(comm, %s)", "JSTR_PAIR(filename, %s)", "
		JSTR_PAIR(page_type, %s)", "JVAL_PAIR(page_index, %lu)", "
		JVAL_PAIR(vm_pgprot, %lu)", "JVAL_PAIR(timestamp, %llu)" }",
		info->event_type, info->pid, info->comm, info->filename,
		info->page_type, info->page_index, info->vm_pgprot,
		info->timestamp);

	if (len < 0 || len > content_len) {
		xpm_log_error("snprintf init integrity failed");
		return -EINVAL;
	}

	return 0;
}

static void xpm_set_report_info(struct xpm_report_param *param,
	struct xpm_report_info *info)
{
	struct fsverity_info *vi = NULL;
	struct file *file = param->file;
	struct mm_struct *mm = current->mm;

	info->event_type = param->event_type;
	info->code_type = code_type_tbl[param->code_type];

	info->pid = current->pid;
	memcpy(info->comm, current->comm, TASK_COMM_LEN);

	if (mm) {
		info->pcs_info.id_type = mm->pcs_info.id_type;
		info->pcs_info.ownerid = mm->pcs_info.ownerid;
	}

	info->vm_prot = param->vm_prot & PROT_MASK;
	if (param->vma) {
		info->vm_pgoff = param->vma->vm_pgoff;
		info->vm_size = param->vma->vm_end - param->vma->vm_start;
		info->vm_pgprot = param->vma->vm_page_prot.pgprot & PROT_MASK;
		file = param->vma->vm_file;
	}

	if (param->page) {
		info->page_type = PageKsm(param->page) ?
			"[ksm]" : PageAnon(param->page) ? "[anon]" : "[file]";
		info->page_index = param->page->index;
	}

	/* init file ownerid type SYSTEM */
	info->fcs_info.id_type = FILE_OWNERID_SYSTEM;
	if (file) {
		xpm_set_filename(file, info);
		vi = fsverity_get_info(file_inode(file));
		if (vi) {
			info->fcs_info.id_type = vi->fcs_info.id_type;
			info->fcs_info.ownerid = vi->fcs_info.ownerid;
		}
	}

	info->timestamp = ktime_get_real_seconds();
}

static int xpm_report_event(struct xpm_report_param *param)
{
	int ret;
	event_info *event = NULL;
	struct xpm_report_info *info = NULL;

	if (!param->event_type) {
		xpm_log_error("xpm event type is NULL");
		return -EINVAL;
	}

	info = kzalloc(sizeof(struct xpm_report_info), GFP_ATOMIC);
	if (!info) {
		xpm_log_error("alloc xpm report info struct failed");
		return -ENOMEM;
	}

	event = kzalloc(sizeof(event_info) + MAX_CONTENT_LEN, GFP_ATOMIC);
	if (!event) {
		xpm_log_error("alloc security guard event failed");
		kfree(info);
		return -ENOMEM;
	}

	do {
		event->version = XPM_EVENT_VERSION;
		event->event_id = param->event_id;

		/* set xpm report info from param */
		xpm_set_report_info(param, info);
		ret = param->set_content(info, event->content, MAX_CONTENT_LEN);
		if (ret) {
			xpm_log_error("type [%s] set content failed",
				param->event_type);
			break;
		}
		event->content_len = strlen(event->content);

		ret = xpm_report_security_info(event);
		if (ret) {
			xpm_log_error("type [%s] report security info failed",
				param->event_type);
			break;
		}

	} while (0);

	kfree(info);
	kfree(event);
	return ret;
}

void report_init_event(char *event_type)
{
	struct xpm_report_param param = {0};

	param.event_type = event_type;
	param.event_id = EVENT_INIT;
	param.set_content = &set_init_content;

	xpm_report_ratelimited(xpm_report_event, &param);
}

void report_file_event(char *event_type, struct file *file)
{
	struct xpm_report_param param = {0};

	param.event_type = event_type;
	param.event_id = EVENT_FILE;
	param.file = file;
	param.set_content = &set_file_content;

	xpm_report_ratelimited(xpm_report_event, &param);
}

void report_mmap_event(char *event_type, enum xpm_code_type code_type,
	struct vm_area_struct *vma, unsigned long vm_prot)
{
	struct xpm_report_param param = {0};

	param.event_type = event_type;
	param.event_id = EVENT_MMAP;
	param.code_type = code_type;
	param.vma = vma;
	param.vm_prot = vm_prot;
	param.set_content = &set_mmap_content;

	xpm_report_ratelimited(xpm_report_event, &param);
}

void report_integrity_event(char *event_type, struct vm_area_struct *vma,
	struct page *page)
{
	struct xpm_report_param param = {0};

	param.event_type = event_type;
	param.event_id = EVENT_INTEGRITY;
	param.vma = vma;
	param.page = page;
	param.set_content = &set_integrity_content;

	xpm_report_ratelimited(xpm_report_event, &param);
}
