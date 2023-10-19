// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 */

#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/compat.h>
#include "avc.h"
#include "objsec.h"
#include "code_sign_ioctl.h"
#include "code_sign_log.h"

struct rb_root cert_chain_tree = RB_ROOT;

struct cert_source *cert_chain_search(struct rb_root *root, struct x509_certificate *cert)
{
	struct rb_node **cur_node = &(root->rb_node);

	while (*cur_node) {
		struct cert_source *cur_cert = container_of(*cur_node, struct cert_source, node);
		int result = strcmp(cert->subject, cur_cert->subject);

		if (result < 0) {
			cur_node = &((*cur_node)->rb_left);
		} else if (result > 0) {
			cur_node = &((*cur_node)->rb_right);
		} else {
			result = strcmp(cert->issuer, cur_cert->issuer);
			if (result < 0) {
				cur_node = &((*cur_node)->rb_left);
			} else if (result > 0) {
				cur_node = &((*cur_node)->rb_right);
			} else {
				code_sign_log_info("cert found");
				return cur_cert;
			}
		}
	}
	code_sign_log_error("cert not found");
	return NULL;
}

struct cert_source *find_match(struct x509_certificate *cert)
{
	return cert_chain_search(&cert_chain_tree, cert);
}

void cert_chain_insert(struct rb_root *root, struct cert_source *cert)
{
	struct rb_node **new = &(root->rb_node), *parent = NULL;

	while (*new) {
		struct cert_source *this = container_of(*new, struct cert_source, node);
		int result = strcmp(cert->subject, this->subject);

		parent = *new;
		if (result < 0) {
			new = &((*new)->rb_left);
		} else if (result > 0) {
			new = &((*new)->rb_right);
		} else {
			result = strcmp(cert->issuer, this->issuer);
			if (result < 0) {
				new = &((*new)->rb_left);
			} else if (result > 0) {
				new = &((*new)->rb_right);
			} else {
				code_sign_log_info("cert already exist in trust sources");
				return;
			}
		}
	}

	// add new node
	rb_link_node(&cert->node, parent, new);
	rb_insert_color(&cert->node, root);
}

int code_sign_open(struct inode *inode, struct file *filp)
{
	return 0;
}

int code_sign_release(struct inode *inode, struct file *filp)
{
	return 0;
}

int code_sign_avc_has_perm(u16 tclass, u32 requested)
{
	struct av_decision avd;
	u32 sid = current_sid();
	int rc, rc2;

	rc = avc_has_perm_noaudit(&selinux_state, sid, sid, tclass, requested,
		AVC_STRICT, &avd);
	rc2 = avc_audit(&selinux_state, sid, sid, tclass, requested, &avd, rc,
		NULL, AVC_STRICT);
	if (rc2)
		return rc2;

	return rc;
}

long code_sign_ioctl(struct file *filp, unsigned int cmd, unsigned long args)
{
	int ret = 0;

	if (code_sign_avc_has_perm(SECCLASS_CODE_SIGN, CODE_SIGN__ADD_CERT_CHAIN)) {
		code_sign_log_error("selinux check failed, no permission to add cert chain");
		return -EPERM;
	}

	if (cmd != WRITE_CERT_CHAIN) {
		code_sign_log_error("code_sign cmd error, cmd: %d", cmd);
		return -EINVAL;
	}

	struct cert_source *source = kzalloc(sizeof(struct cert_source), GFP_KERNEL);

	if (!source)
		return -ENOMEM;


	struct cert_chain_info info;

	if (copy_from_user(&info, args, sizeof(struct cert_chain_info))) {
		code_sign_log_error("cmd copy_from_user failed");
		ret = -ENOMEM;
		goto copy_source_failed;
	}

	if (info.path_len > CERT_CHAIN_PATH_LEN_MAX) {
		code_sign_log_error("invalid path len: %d", info.path_len);
		ret = -EINVAL;
		goto copy_source_failed;
	}

	source->subject = kzalloc(info.signing_length, GFP_KERNEL);
	if (!source->subject) {
		ret = -ENOMEM;
		goto copy_source_failed;
	}

	if (copy_from_user(source->subject, u64_to_user_ptr(info.signing_ptr), info.signing_length)) {
		code_sign_log_error("copy_from_user get signing failed");
		ret = -EFAULT;
		goto copy_subject_failed;
	}

	source->issuer = kzalloc(info.issuer_length, GFP_KERNEL);
	if (!source->issuer) {
		ret = -ENOMEM;
		goto copy_subject_failed;
	}

	ret = copy_from_user(source->issuer, u64_to_user_ptr(info.issuer_ptr), info.issuer_length);
	if (ret) {
		code_sign_log_error("copy_from_user get issuer failed");
		ret = -EFAULT;
		goto copy_issuer_failed;
	}

	source->max_path_depth = info.path_len;

	code_sign_log_info("add trusted cert: subject = '%s', issuer = '%s', max_path_depth = %d",
		source->subject, source->issuer, source->max_path_depth);

	// insert rb_tree
	cert_chain_insert(&cert_chain_tree, source);

	return ret;

copy_issuer_failed:
	kfree(source->issuer);
copy_subject_failed:
	kfree(source->subject);
copy_source_failed:
	kfree(source);
	return ret;
}
