KERNEL_DIR :=$(srctree)

ifneq ($(TARGET_BUILD_VARIANT),user)
	ccflags-y += -DDEF_ENG
endif

EXTRA_CFLAGS += -I$(KERNEL_DIR)/drivers/tzdriver
EXTRA_CFLAGS += -I$(KERNEL_DIR)/drivers/tzdriver/core
EXTRA_CFLAGS += -I$(KERNEL_DIR)/drivers/staging/android

obj-$(CONFIG_STATIC_ION) += static_ion_mem.o
obj-$(CONFIG_DYNAMIC_ION) += dynamic_ion_mem.o
ifneq ($(CONFIG_MTK_PLATFORM), )
obj-$(CONFIG_STATIC_ION) += mplat/declare_static_ion.o
else
obj-$(CONFIG_STATIC_ION) += generic/declare_static_ion.o
endif

EXTRA_CFLAGS += -I$(KERNEL_DIR)/drivers/tzdriver/include
EXTRA_CFLAGS += -include internal_functions.h