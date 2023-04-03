/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 */

#ifndef _BTDEV_H_
#define _BTDEV_H_

#include <linux/skbuff.h>
#include <linux/list.h>
#include <linux/errno.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/fcntl.h>
#include <linux/ioport.h>
#include <linux/in.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/bitops.h>
#include <linux/delay.h>
#include <linux/ip.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/poll.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/ktime.h>
#include <linux/rtnetlink.h>

/* must include btdev_user.h first before any macro definition */
#include "btdev_user.h"

#define OK 0
#define DELAY_100_MS 100
#define MACADDR_LEN (2 * ETH_ALEN)

#define BT_DEV_MAJOR 125
#define BT_DEV_MINOR 0
#define BT_RING_BUFFER_SIZE 4096
#define STRTOLL_BASE 10
#define BT_DEV_ID_OFFSET (sizeof(BT_DEV_PATH_PREFIX) - 1)
#define BT_STATISTIC_KTIME_MAX ULONG_MAX

/**
 * for debug
 */
#define DEBUG

/**
 * ring buffer
 */
struct bt_ring {
	u32 head;
	u32 tail;
	u32 size;
	void **data;
};

/**
 * one char device
 */
struct bt_cdev {
	struct cdev *cdev;
	struct class *bt_class;
	char dev_filename[BT_PATHNAME_MAX];
};

struct bt_mng_file {
	struct bt_cdev *bt_cdev;
	atomic_t open_limit;
};

struct bt_io_file {
	struct bt_cdev *bt_cdev;
	atomic_t read_open_limit;
	atomic_t write_open_limit;
};

/**
 * virnet list
 */
struct bt_table {
	struct list_head head;
	struct mutex tbl_lock; // lock for table
	u32 num;
};

/**
 * bt virnet state
 */
enum bt_virnet_state {
	BT_VIRNET_STATE_CREATED,
	BT_VIRNET_STATE_CONNECTED,
	BT_VIRNET_STATE_DISCONNECTED,
	BT_VIRNET_STATE_DISABLED,
	BT_VIRNET_STATE_DELETED,
	BT_VIRNET_STAET_NUM
};

/**
 * one virnet device
 */
struct bt_virnet {
	struct bt_ring *tx_ring;
	struct bt_io_file *io_file;
	struct net_device *ndev;
	struct list_head virnet_entry;
	struct bt_table *bt_table_head;
	enum bt_virnet_state state;
	struct semaphore sem;
	wait_queue_head_t rx_queue, tx_queue;
};

/**
 * instance of the module
 */
struct bt_drv {
	struct bt_table *devices_table;
	struct bt_mng_file *mng_file;
	struct bt_io_file **io_files;
	u32 bitmap;
	struct mutex bitmap_lock; // lock for bitmap
	struct class *bt_class;
};

/**
 * state to string
 */
static const char *bt_virnet_state_rep[BT_VIRNET_STAET_NUM] = {
	"CREATED",
	"CONNECTED",
	"DISCONNECTED",
	"DISABLED",
	"ENABLED"};

/**
 * inline functions
 */
static inline int bt_get_unused_id(const u32 *bitmap)
{
	int i;

	WARN_ON(!bitmap);
	for (i = 0; i < BT_VIRNET_MAX_NUM + 1; ++i) {
		if (!(*bitmap & (1 << i)))
			return i;
	}
	return -1; // all used
}

static inline void bt_set_bit(u32 *bitmap, u32 idx)
{
	WARN_ON(!bitmap);
	*bitmap |= (1 << idx);
}

static inline void bt_clear_bit(u32 *bitmap, u32 idx)
{
	WARN_ON(!bitmap);
	*bitmap &= ~(1 << idx);
}

#define SET_STATE(vn, st) bt_virnet_set_state(vn, st)
static inline void bt_virnet_set_state(struct bt_virnet *vn,
				       enum bt_virnet_state state)
{
	WARN_ON(!vn);
	vn->state = state;
}

static inline const struct cdev *bt_virnet_get_cdev(const struct bt_virnet *vn)
{
	WARN_ON(!vn);
	return vn->io_file->bt_cdev->cdev;
}

static inline const dev_t bt_virnet_get_cdev_number(const struct bt_virnet *vn)
{
	WARN_ON(!vn);
	return vn->io_file->bt_cdev->cdev->dev;
}

static inline const char *bt_virnet_get_cdev_name(const struct bt_virnet *vn)
{
	WARN_ON(!vn);
	return vn->io_file->bt_cdev->dev_filename;
}

static inline struct net_device *bt_virnet_get_ndev(const struct bt_virnet *vn)
{
	WARN_ON(!vn);
	return vn->ndev;
}

static inline const char *bt_virnet_get_ndev_name(const struct bt_virnet *vn)
{
	WARN_ON(!vn);
	return vn->ndev->name;
}

static inline const char *bt_virnet_get_state_rep(const struct bt_virnet *vn)
{
	WARN_ON(!vn);
	return bt_virnet_state_rep[vn->state];
}

static inline int bt_get_total_device(const struct bt_drv *bt_drv)
{
	WARN_ON(!bt_drv);
	return bt_drv->devices_table->num;
}

static inline int bt_virnet_get_ring_packets(const struct bt_virnet *vn)
{
	int packets = 0;

	WARN_ON(!vn);
	packets = vn->tx_ring->head - vn->tx_ring->tail;
	if (unlikely(packets < 0))
		packets += BT_RING_BUFFER_SIZE;

	return packets;
}

static struct bt_table *bt_table_init(void);
static int bt_table_add_device(struct bt_table *tbl, struct bt_virnet *vn);
static void bt_table_remove_device(struct bt_table *tbl, struct bt_virnet *vn);
static void bt_table_delete_all(struct bt_drv *bt_drv);
static struct bt_virnet *bt_table_find(struct bt_table *tbl, const char *ifa_name);
static void bt_table_destroy(struct bt_drv *bt_drv);
static void bt_delete_io_files(struct bt_drv *bt_mng);
static struct bt_io_file **bt_create_io_files(void);

static struct bt_ring *bt_ring_create(void);
static int bt_ring_is_empty(const struct bt_ring *ring);
static int bt_ring_is_full(const struct bt_ring *ring);
static void *bt_ring_current(struct bt_ring *ring);
static void bt_ring_produce(struct bt_ring *ring, void *data);
static void bt_ring_consume(struct bt_ring *ring);
static void bt_ring_destroy(struct bt_ring *ring);

static int bt_virnet_produce_data(struct bt_virnet *dev, void *data);
static struct bt_virnet *bt_virnet_create(struct bt_drv *bt_mng, u32 id);
static void bt_virnet_destroy(struct bt_virnet *vnet);

#endif
