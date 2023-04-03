/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 */

#ifndef _BTDEV_USER_H_
#define _BTDEV_USER_H_

#include <linux/if.h>
#include <linux/ioctl.h>

#define BT_VIRNET_NAME_PREFIX "btn"
#define BT_DEV_NAME_PREFIX "btdev"
#define BT_DEV_PATH_PREFIX "/dev/" BT_DEV_NAME_PREFIX

#define BT_DEV_PATH(idx) (BT_DEV_PATH_PREFIX#idx)
#define BT_DEV_NAME(idx) (BT_DEV_NAME_PREFIX#idx)

#define BT_DEV_NAME_MNG_FILE BT_DEV_NAME(0)
#define BT_DEV_PATH_MNG_FILE BT_DEV_PATH(0)
#define BT_DEV_NAME_IO_FILE(idx) BT_DEV_NAME(idx)
#define BT_DEV_PATH_IO_FILE(idx) BT_DEV_PATH(idx)
#define BT_VIRNET_NAME(idx) (BT_VIRNET_NAME_PREFIX#idx)

#define BT_PATHNAME_MAX 256
#define BT_VIRNET_MAX_NUM 16
#define BT_VIRNET_DATA_HEAD_LEN 2

/**
 * ioctl cmd
 */
#define BT_IOC_CREATE _IO('b', 1)
#define BT_IOC_DELETE _IO('b', 2)
#define BT_IOC_CHANGE_MTU _IO('b', 3)
#define BT_IOC_QUERY_ALL _IO('b', 4)
#define BT_IOC_DELETE_ALL _IO('b', 5)
#define BT_IOC_ENABLE _IO('b', 6)
#define BT_IOC_DISABLE _IO('b', 7)
#define BT_IOC_PEEK_PACKET _IO('b', 8)

/**
 * user space ioctl arguments
 */
struct bt_uioc_args {
	char ifa_name[IFNAMSIZ];
	char cfile_name[BT_PATHNAME_MAX];
};

#endif
