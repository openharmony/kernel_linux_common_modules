# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2023 Huawei Device Co., Ltd.
#
# Makefile for the ecutable permission manager module
#

obj-$(CONFIG_SECURITY_XPM) += \
	core/xpm_common.o \
	core/xpm_module.o \
	core/xpm_misc_device.o \
	core/xpm_hck_hooks.o \
	core/xpm_security_hooks.o \
	core/xpm_report.o \
	validator/elf_code_segment_info.o \
	validator/exec_signature_info.o \
	developer/dsmm_developer.o \
	secureshield/dsmm_secureshield.o

obj-$(CONFIG_SECURITY_XPM_DEBUG) += \
	core/xpm_debugfs.o

ccflags-$(CONFIG_SECURITY_XPM) += \
	-I$(srctree)/security/xpm/core \
	-I$(srctree)/security/xpm/validator \
	-I$(srctree)/security/xpm/developer \
	-I$(srctree)/security/xpm/secureshield \
	-I$(srctree)/security/selinux/include \
	-I$(srctree)/security/selinux \
	-I$(srctree)/fs \
	-I$(srctree)/fs/verity \
	-I$(srctree)/fs/code_sign

$(addprefix $(obj)/,$(obj-y)): $(obj)/flask.h

quiet_cmd_flask = GEN $(obj)/flask.h $(obj)/av_permissions.h
      cmd_flask = scripts/selinux/genheaders/genheaders $(obj)/flask.h $(obj)/av_permissions.h

targets += flask.h av_permissions.h
$(obj)/flask.h: $(srctree)/security/selinux/include/classmap.h FORCE
	$(call if_changed,flask)
