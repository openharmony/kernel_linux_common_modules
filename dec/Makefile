# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (c) 2024 Huawei Device Co., Ltd.
#
obj-$(CONFIG_SECURITY_DEC)	+= \
	dec_misc.o

ccflags-$(CONFIG_SECURITY_DEC) += \
	-I$(srctree)/fs/dec 

$(addprefix $(obj)/,$(obj-y)): $(obj)/flask.h

quiet_cmd_flask = GEN $(obj)/flask.h $(obj)/av_permissions.h
      cmd_flask = scripts/selinux/genheaders/genheaders $(obj)/flask.h $(obj)/av_permissions.h

targets += flask.h av_permissions.h
$(obj)/flask.h: $(srctree)/security/selinux/include/classmap.h FORCE
	$(call if_changed,flask)
