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

#define bt_dev_path(idx) (BT_DEV_PATH_PREFIX#idx)
#define bt_dev_name(idx) (BT_DEV_NAME_PREFIX#idx)

#define BT_DEV_NAME_MNG_FILE bt_dev_name(0)
#define BT_DEV_PATH_MNG_FILE bt_dev_path(0)
#define bt_dev_name_to_file(idx) bt_dev_name(idx)
#define bt_dev_path_to_file(idx) bt_dev_path(idx)
#define bt_virnet_name(idx) (BT_VIRNET_NAME_PREFIX#idx)

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
	char cfile_name[IFNAMSIZ];
};

#endif
