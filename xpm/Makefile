# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2023 Huawei Device Co., Ltd.
#
# Makefile for the ecutable permission manager module
#

obj-$(CONFIG_SECURITY_XPM) += \
	core/xpm_module.o \
	core/xpm_misc.o \
	core/xpm_hck.o \
	core/xpm_report.o \
	core/dsmm_developer.o \
	validator/elf_code_segment_info.o \
	validator/exec_signature_info.o

obj-$(CONFIG_SECURITY_XPM_DEBUG) += \
	core/xpm_debugfs.o

ccflags-$(CONFIG_SECURITY_XPM) += \
	-I$(srctree)/security/xpm/include \
	-I$(srctree)/security/selinux/include \
	-I$(srctree)/security/selinux \
	-I$(srctree)/fs \
	-I$(srctree)/fs/code_sign

$(addprefix $(obj)/,$(obj-y)): $(obj)/flask.h

quiet_cmd_flask = GEN $(obj)/flask.h $(obj)/av_permissions.h
      cmd_flask = scripts/selinux/genheaders/genheaders $(obj)/flask.h $(obj)/av_permissions.h

targets += flask.h av_permissions.h
$(obj)/flask.h: $(srctree)/security/selinux/include/classmap.h FORCE
	$(call if_changed,flask)
