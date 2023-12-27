ifeq ($(CONFIG_TZDRIVER),y)
KERNEL_DIR := $(srctree)

EXTRA_CFLAGS += -I$(KERNEL_DIR)/../../../../third_party/bounds_checking_function/include/

obj-$(CONFIG_TZDRIVER) += agent_rpmb/
obj-$(CONFIG_TZDRIVER) += auth/
obj-$(CONFIG_TZDRIVER) += core/
obj-$(CONFIG_TZDRIVER) += tlogger/
obj-$(CONFIG_TZDRIVER) += ion/
obj-$(CONFIG_TZDRIVER) += tui/
obj-$(CONFIG_TZDRIVER) += whitelist/

endif
