# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2023 Huawei Device Co., Ltd.
#
# Makefile for memory_security manager module
#
obj-$(CONFIG_HIDE_MEM_ADDRESS) += \
	src/hideaddr.o \
	module.o

obj-$(CONFIG_JIT_MEM_CONTROL) += \
	src/jit_space_list.o \
	src/jit_process.o \
	src/jit_memory.o \
	src/jit_memory_module.o \
	module.o

ccflags-$(CONFIG_HIDE_MEM_ADDRESS) += \
	-I$(srctree)/fs/proc \
	-I$(srctree)/fs/proc/memory_security/include \
	-I$(srctree)/security/selinux/include \
	-I$(srctree)/security/selinux

ccflags-$(CONFIG_JIT_MEM_CONTROL) += \
	-I$(srctree)/fs/proc \
	-I$(srctree)/fs/proc/memory_security/include \
	-I$(srctree)/security/selinux/include \
	-I$(srctree)/security/selinux

$(addprefix $(obj)/,$(obj-y)): $(obj)/flask.h

quiet_cmd_flask = GEN $(obj)/flask.h $(obj)/av_permissions.h
      cmd_flask = scripts/selinux/genheaders/genheaders $(obj)/flask.h $(obj)/av_permissions.h

targets += flask.h av_permissions.h
$(obj)/flask.h: $(srctree)/security/selinux/include/classmap.h FORCE
	$(call if_changed,flask)
