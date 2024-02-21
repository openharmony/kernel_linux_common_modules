// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 *
 * Description: Bluetooth virtual network device used in
 * the NewIP over Bluetooth communication scenario.
 *
 * Author: Yang Yanjun <yangyanjun@huawei.com>
 *
 * Data: 2023-03-14
 */

#define pr_fmt(fmt) "newip-bt: [%s:%d] " fmt, __func__, __LINE__

#include "btdev.h"

#define ndev_name(vnet)  bt_virnet_get_ndev_name(vnet)  /* btn1/2/3/4/... */
#define cdev_name(vnet)  bt_virnet_get_cdev_name(vnet)  /* dev/btdev1/2/3/4/... */

/* /sys/module/btdev/parameters/btdev_debug */
bool g_btdev_debug;
module_param_named(btdev_debug, g_btdev_debug, bool, 0644);

#define btdev_dbg(fmt, ...) \
do { \
	if (g_btdev_debug) \
		pr_crit(fmt, ##__VA_ARGS__); \
} while (0)

#define btdev_dbg_err(fmt, ...) pr_err(fmt, ##__VA_ARGS__)

static struct bt_drv *g_bt_drv;

static int bt_seq_show(struct seq_file *m, void *v)
{
	struct bt_virnet *vnet = NULL;

	if (unlikely(!g_bt_drv)) {
		btdev_dbg_err("invalid bt_drv");
		return -EINVAL;
	}

	seq_printf(m, "Total device: %d (bitmap: 0x%X) Ring size: %d\n",
		   bt_get_total_device(g_bt_drv), g_bt_drv->bitmap,
		   BT_RING_BUFFER_SIZE);

	list_for_each_entry(vnet, &g_bt_drv->devices_table->head, virnet_entry) {
		seq_printf(m, "dev: %12s, interface: %7s, state: %12s, MTU: %4d\n",
			   cdev_name(vnet), ndev_name(vnet),
			   bt_virnet_get_state_rep(vnet), vnet->ndev->mtu);
		seq_printf(m, "ring head: %4d, ring tail: %4d, packets num: %4d\n",
			   vnet->tx_ring->head, vnet->tx_ring->tail,
			   bt_virnet_get_ring_packets(vnet));
	}

	return OK;
}

static int bt_proc_open(struct inode *inode, struct file *file)
{
	if (unlikely(!inode) || unlikely(!file)) {
		btdev_dbg_err("invalid parameter");
		return -EINVAL;
	}

	return single_open(file, bt_seq_show, PDE_DATA(inode));
}

static struct proc_ops g_bt_proc_fops = {
	.proc_open = bt_proc_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release};

static int __bt_virnet_open(struct file *filp, struct bt_virnet *vnet)
{
	struct net_device *ndev;

	if ((filp->f_flags & O_ACCMODE) == O_RDONLY) {
		/* Check whether xx_open_limit is equal to 0 after subtracting 1.
		 * If so, return true
		 */
		if (unlikely(!atomic_dec_and_test(&vnet->io_file->read_open_limit)))
			goto read_twice_already;
	} else if ((filp->f_flags & O_ACCMODE) == O_WRONLY) {
		if (unlikely(!atomic_dec_and_test(&vnet->io_file->write_open_limit)))
			goto write_twice_already;
	} else if ((filp->f_flags & O_ACCMODE) == O_RDWR) {
		if (unlikely(!atomic_dec_and_test(&vnet->io_file->read_open_limit)))
			goto read_twice_already;
		if (unlikely(!atomic_dec_and_test(&vnet->io_file->write_open_limit)))
			goto write_twice_already;
	}

	/* Set xx_open_limit to 0 when the file is first opened */
	rtnl_lock();
	ndev = vnet->ndev;
	if (unlikely(!(ndev->flags & IFF_UP))) {
		int ret = dev_change_flags(ndev, ndev->flags | IFF_UP, NULL);

		if (unlikely(ret < 0)) {
			rtnl_unlock();
			btdev_dbg_err("%s dev change flags failed, ret=%d", cdev_name(vnet), ret);
			return -EBUSY;
		}
	}
	rtnl_unlock();

	set_state(vnet, BT_VIRNET_STATE_CONNECTED);
	filp->private_data = vnet;
	btdev_dbg("%s has been opened", cdev_name(vnet));
	return OK;

	/* If the file is not opened for the first time, an error occurs
	 * and xx_open_limit is restored to the open state. (set to 0)
	 */
read_twice_already:
	atomic_inc(&vnet->io_file->read_open_limit);
	btdev_dbg_err("%s has been opened for read twice already", cdev_name(vnet));
	return -EBUSY;

write_twice_already:
	atomic_inc(&vnet->io_file->write_open_limit);
	btdev_dbg_err("%s has been opened for write twice already", cdev_name(vnet));
	return -EBUSY;
}

static int bt_io_file_open(struct inode *node, struct file *filp)
{
	struct bt_virnet *vnet = NULL;

	if (unlikely(!node) || unlikely(!filp)) {
		btdev_dbg_err("invalid parameter");
		return -EINVAL;
	}

	list_for_each_entry(vnet, &g_bt_drv->devices_table->head, virnet_entry) {
		if (bt_virnet_get_cdev(vnet) == node->i_cdev)
			return __bt_virnet_open(filp, vnet);
	}
	return -EIO;
}

static int bt_io_file_release(struct inode *node, struct file *filp)
{
	struct bt_virnet *vnet = NULL;

	if (unlikely(!filp) || unlikely(!filp->private_data)) {
		btdev_dbg_err("invalid parameter");
		return -EINVAL;
	}

	vnet = filp->private_data;
	btdev_dbg("%s has been released", cdev_name(vnet));

	/* Set xx_open_limit to 1 when the file is closed */
	if ((filp->f_flags & O_ACCMODE) == O_RDONLY) {
		atomic_inc(&vnet->io_file->read_open_limit);
	} else if ((filp->f_flags & O_ACCMODE) == O_WRONLY) {
		atomic_inc(&vnet->io_file->write_open_limit);
	} else if ((filp->f_flags & O_ACCMODE) == O_RDWR) {
		atomic_inc(&vnet->io_file->read_open_limit);
		atomic_inc(&vnet->io_file->write_open_limit);
	}

	set_state(vnet, BT_VIRNET_STATE_DISCONNECTED);

	return OK;
}

static ssize_t bt_io_file_read(struct file *filp,
			       char __user *buffer,
			       size_t size, loff_t *off)
{
	struct bt_virnet *vnet = NULL;
	ssize_t out_sz;
	struct sk_buff *skb = NULL;

	if (unlikely(!filp) || unlikely(!buffer) || unlikely(!filp->private_data)) {
		btdev_dbg_err("invalid parameter");
		return -EINVAL;
	}

	vnet = filp->private_data;
	while (unlikely(bt_ring_is_empty(vnet->tx_ring))) {
		if (filp->f_flags & O_NONBLOCK)
			return -EAGAIN;

		if (wait_event_interruptible(vnet->rx_queue, !bt_ring_is_empty(vnet->tx_ring)))
			return -ERESTARTSYS;
	}

	skb = bt_ring_current(vnet->tx_ring);
	if (unlikely(!skb)) {
		btdev_dbg_err("%s invalid skb", cdev_name(vnet));
		return -EINVAL;
	}
	out_sz = skb->len > MACADDR_LEN ? (skb->len - MACADDR_LEN) : 0;
	if (unlikely(out_sz > size) || unlikely(out_sz == 0)) {
		/* Obtain the skb pointer from the ring buf and ask whether the user-state buf
		 * length can store data in the skb. If the user-state buf length is not enough,
		 * the skb cannot be released at this time, because the skb is still unchained
		 * on the ring buf.
		 */
		btdev_dbg_err("%s usr-buf too small, skb-len=%ld, usr-buf-len=%ld, skb-len=%u",
			      cdev_name(vnet), (long)out_sz, (long)size, skb->len);
		return -EINVAL;
	}

	bt_ring_consume(vnet->tx_ring);
	if (copy_to_user(buffer, skb->data + MACADDR_LEN, out_sz)) {
		/* The skb pointer is obtained from the ring buf and the skb has been unchained
		 * from the ring buf. In this case, the skb needs to be released when the skb data
		 * fails to be copied to the user mode.
		 */
		btdev_dbg_err("%s copy to user failed", cdev_name(vnet));
		dev_kfree_skb(skb);
		return -EIO;
	}
	dev_kfree_skb(skb);

	btdev_dbg("read %ld data from %s", (long)out_sz, cdev_name(vnet));
	if (unlikely(netif_queue_stopped(vnet->ndev))) {
		btdev_dbg("consume data: wake the queue");
		netif_wake_queue(vnet->ndev);
	}

	return out_sz;
}

static ssize_t bt_io_file_write(struct file *filp,
				const char __user *buffer,
				size_t size, loff_t *off)
{
	struct bt_virnet *vnet = NULL;
	struct sk_buff *skb = NULL;
	int ret;
	int len;
	ssize_t in_sz;

	if (unlikely(!filp) || unlikely(!buffer) || unlikely(!filp->private_data)) {
		btdev_dbg_err("invalid parameter");
		return -EINVAL;
	}

	vnet = filp->private_data;
	in_sz = size + MACADDR_LEN;

	/* Ethernet head length: DMAC(6B) + SMAC(6B) + eth-type(2B) */
	skb = netdev_alloc_skb(bt_virnet_get_ndev(vnet), in_sz + NEWIP_TYPE_SIZE);
	if (unlikely(!skb))
		return -ENOMEM;

	skb_reserve(skb, NEWIP_TYPE_SIZE);
	skb_put(skb, in_sz);

	memset(skb->data, 0, MACADDR_LEN);
	if (copy_from_user(skb->data + MACADDR_LEN, buffer, size)) {
		btdev_dbg_err("%s copy from user failed", cdev_name(vnet));
		dev_kfree_skb(skb);
		return -EIO;
	}

	len = skb->len;
	skb->dev = bt_virnet_get_ndev(vnet);
	skb->protocol = eth_type_trans(skb, bt_virnet_get_ndev(vnet));
	ret = netif_rx_ni(skb);

	if (ret == NET_RX_SUCCESS) {
		btdev_dbg("write %lu bytes data to %s", size, cdev_name(vnet));
		vnet->ndev->stats.rx_packets++;
		vnet->ndev->stats.rx_bytes += len;
	} else {
		btdev_dbg_err("failed to write %lu bytes data to %s", size, cdev_name(vnet));
		vnet->ndev->stats.rx_errors++;
		vnet->ndev->stats.rx_dropped++;
	}

	return size;
}

static int bt_virnet_change_mtu(struct net_device *dev, int mtu)
{
	if (unlikely(!dev) || unlikely(mtu < 0) || unlikely(mtu > BT_MAX_MTU)) {
		btdev_dbg_err("invalid parameter");
		return -EINVAL;
	}
	btdev_dbg("change %s mtu %u to %u", dev->name, dev->mtu, mtu);
	dev->mtu = mtu;
	return OK;
}

static int bt_set_mtu(struct net_device *dev, int mtu)
{
	int err = OK;

	if (unlikely(mtu < 0) || unlikely(mtu > BT_MAX_MTU)) {
		btdev_dbg_err("invalid parameter");
		return -EINVAL;
	}

	rtnl_lock();
	err = dev_set_mtu(dev, mtu);
	rtnl_unlock();
	if (err < 0)
		btdev_dbg_err("failed to set %s mtu to %d, err=%d", dev->name, mtu, err);
	else
		btdev_dbg("set %s mtu to %d", dev->name, mtu);

	return err;
}

static int bt_cmd_enable_virnet(struct bt_virnet *vnet, unsigned long arg)
{
	int ret;

	if (unlikely(vnet->state != BT_VIRNET_STATE_DISABLED)) {
		btdev_dbg_err("%s enable can only be set at disabled state", cdev_name(vnet));
		return -EINVAL; // enable failed
	}

	rtnl_lock();
	ret = dev_change_flags(vnet->ndev, vnet->ndev->flags | IFF_UP, NULL);
	rtnl_unlock();
	if (unlikely(ret < 0)) {
		btdev_dbg_err("%s dev change flags failed, ret=%d", cdev_name(vnet), ret);
		return -EIO;
	}

	btdev_dbg("%s has been enabled", cdev_name(vnet));
	set_state(vnet, BT_VIRNET_STATE_CONNECTED);
	return OK;
}

static int bt_cmd_disable_virnet(struct bt_virnet *vnet, unsigned long arg)
{
	int ret;

	if (unlikely(vnet->state != BT_VIRNET_STATE_CONNECTED)) {
		btdev_dbg_err("%s disable can only be set at connected state", cdev_name(vnet));
		return -EINVAL;
	}

	rtnl_lock();
	ret = dev_change_flags(vnet->ndev, vnet->ndev->flags & ~IFF_UP, NULL);
	rtnl_unlock();
	if (unlikely(ret < 0)) {
		btdev_dbg_err("%s dev change flags failed, ret=%d", cdev_name(vnet), ret);
		return -EIO;
	}

	btdev_dbg("%s has been disabled", cdev_name(vnet));
	set_state(vnet, BT_VIRNET_STATE_DISABLED);
	return OK;
}

static int bt_cmd_change_mtu(struct bt_virnet *vnet, unsigned long arg)
{
	int mtu;
	int ret;

	if (unlikely(get_user(mtu, (int __user *)arg))) {
		btdev_dbg_err("%s get user failed", ndev_name(vnet));
		return -EIO;
	}

	ret = bt_set_mtu(vnet->ndev, mtu);
	if (unlikely(ret < 0)) {
		btdev_dbg_err("%s changed mtu to %d failed", ndev_name(vnet), mtu);
		return -EIO;
	}

	btdev_dbg("%s changed mtu to %d", ndev_name(vnet), mtu);
	return OK;
}

static int bt_cmd_peek_packet(struct bt_virnet *vnet, unsigned long arg)
{
	u32 len;
	struct sk_buff *skb;

	if (unlikely(bt_ring_is_empty(vnet->tx_ring))) {
		btdev_dbg_err("%s ring is empty", ndev_name(vnet));
		return -EAGAIN;
	}

	/* The user state retrieves the data length from the ring buf, rather than
	 * unchain the skb from the ring buf, so there is no need to release the skb
	 */
	skb = bt_ring_current(vnet->tx_ring);
	if (unlikely(!skb)) {
		btdev_dbg_err("%s invalid skb", ndev_name(vnet));
		return -EINVAL;
	}

	len = skb->len - MACADDR_LEN;
	if (unlikely(put_user(len, (int __user *)arg))) {
		btdev_dbg_err("%s put_user failed", ndev_name(vnet));
		return -EIO;
	}

	btdev_dbg("%s get packet len is %u", ndev_name(vnet), len);
	return OK;
}

static long bt_io_file_ioctl(struct file *filep,
			     unsigned int cmd,
			     unsigned long arg)
{
	long ret;
	struct bt_virnet *vnet = NULL;

	if (unlikely(!filep) || unlikely(!filep->private_data)) {
		btdev_dbg_err("invalid parameter");
		return -EINVAL;
	}
	vnet = filep->private_data;
	switch (cmd) {
	case BT_IOC_CHANGE_MTU:
		ret = bt_cmd_change_mtu(vnet, arg);
		break;
	case BT_IOC_ENABLE:
		ret = bt_cmd_enable_virnet(vnet, arg);
		break;
	case BT_IOC_DISABLE:
		ret = bt_cmd_disable_virnet(vnet, arg);
		break;
	case BT_IOC_PEEK_PACKET:
		ret = bt_cmd_peek_packet(vnet, arg);
		break;
	default:
		btdev_dbg_err("not a valid cmd(%u)", cmd);
		return -ENOIOCTLCMD;
	}

	return ret;
}

static unsigned int bt_io_file_poll(struct file *filp, poll_table *wait)
{
	struct bt_virnet *vnet = NULL;
	unsigned int mask = 0;

	if (unlikely(!filp) || unlikely(!wait) || unlikely(!filp->private_data)) {
		btdev_dbg_err("invalid parameter");
		return -EINVAL;
	}
	vnet = filp->private_data;
	poll_wait(filp, &vnet->rx_queue, wait);

	if (!bt_ring_is_empty(vnet->tx_ring)) // readable
		mask |= POLLIN | POLLRDNORM;

	if (!bt_ring_is_full(vnet->tx_ring)) // writable
		mask |= POLLOUT | POLLWRNORM;

	return mask;
}

static const struct file_operations g_bt_io_file_ops = {
	.owner = THIS_MODULE,
	.open = bt_io_file_open,
	.release = bt_io_file_release,
	.read = bt_io_file_read,
	.write = bt_io_file_write,
	.poll = bt_io_file_poll,
	.unlocked_ioctl = bt_io_file_ioctl,
	.compat_ioctl = bt_io_file_ioctl};

static int bt_mng_file_open(struct inode *node, struct file *filp)
{
	if (unlikely(!filp)) {
		btdev_dbg_err("bt mng file open: invalid filp");
		return -EINVAL;
	}

	/* Check whether open_limit is equal to 0 after subtracting 1. If so, return true */
	if (unlikely(!atomic_dec_and_test(&g_bt_drv->mng_file->open_limit))) {
		/* If the file is not opened for the first time, an error occurs
		 * and open_limit is restored to the open state. (set to 0)
		 */
		atomic_inc(&g_bt_drv->mng_file->open_limit);
		btdev_dbg_err("file %s has been opened already",
			      g_bt_drv->mng_file->bt_cdev->dev_filename);
		return -EBUSY;
	}

	/* open_limit becomes 0 after the file is first opened */
	filp->private_data = g_bt_drv;

	btdev_dbg("%s has been opened", g_bt_drv->mng_file->bt_cdev->dev_filename);
	return OK;
}

static int bt_mng_file_release(struct inode *node, struct file *filp)
{
	struct bt_drv *drv = NULL;

	if (unlikely(!filp) || unlikely(!filp->private_data)) {
		btdev_dbg_err("invalid parameter");
		return -EINVAL;
	}
	drv = filp->private_data;

	/* Set open_limit to 1 when the file is closed */
	atomic_inc(&drv->mng_file->open_limit);

	btdev_dbg("%s has been released", g_bt_drv->mng_file->bt_cdev->dev_filename);
	return OK;
}

static int bt_cmd_create_virnet(struct bt_drv *bt_mng, unsigned long arg)
{
	int id;
	int ret;
	struct bt_virnet *vnet = NULL;
	struct bt_uioc_args vp;
	unsigned long size;

	mutex_lock(&bt_mng->bitmap_lock);
	id = bt_get_unused_id(bt_mng->bitmap);
	if ((unlikely(bt_mng->devices_table->num >= BT_VIRNET_MAX_NUM)) ||
	    (unlikely(id < 0))) {
		btdev_dbg_err("reach the limit of max virnets");
		goto virnet_create_failed;
	}
	vnet = bt_virnet_create(bt_mng, id);
	if (unlikely(!vnet)) {
		btdev_dbg_err("bt virnet create failed");
		goto virnet_create_failed;
	}

	ret = bt_table_add_device(bt_mng->devices_table, vnet);
	if (unlikely(ret < 0)) {
		btdev_dbg_err("bt table add device failed: ret=%d", ret);
		goto add_device_failed;
	}

	bt_set_bit(&bt_mng->bitmap, id);
	mutex_unlock(&bt_mng->bitmap_lock);

	memcpy(vp.ifa_name, ndev_name(vnet), sizeof(vp.ifa_name));
	memcpy(vp.cfile_name, cdev_name(vnet), sizeof(vp.cfile_name));

	mdelay(DELAY_100_MS);

	size = copy_to_user((void __user *)arg, &vp, sizeof(struct bt_uioc_args));
	if (unlikely(size)) {
		btdev_dbg_err("copy_to_user failed: left size=%lu", size);
		goto copy_to_user_failed;
	}

	btdev_dbg("%s has been created", ndev_name(vnet));
	return OK;

copy_to_user_failed:
	mutex_lock(&bt_mng->bitmap_lock);
	bt_table_remove_device(bt_mng->devices_table, vnet);
	bt_clear_bit(&bt_mng->bitmap, id);

add_device_failed:
	bt_virnet_destroy(vnet);

virnet_create_failed:
	mutex_unlock(&bt_mng->bitmap_lock);
	return -EIO;
}

static int bt_cmd_delete_virnet(struct bt_drv *bt_mng, unsigned long arg)
{
	int err;
	struct bt_virnet *vnet = NULL;
	struct bt_uioc_args vp;
	unsigned long size;
	dev_t number;

	size = copy_from_user(&vp, (void __user *)arg,
			      sizeof(struct bt_uioc_args));
	if (unlikely(size)) {
		btdev_dbg_err("copy_from_user failed: left size=%lu", size);
		return -EIO;
	}

	vnet = bt_table_find(bt_mng->devices_table, vp.ifa_name);
	if (unlikely(!vnet)) {
		btdev_dbg_err("virnet: %s cannot be found in bt table", vp.ifa_name);
		return -EIO; // not found
	}

	btdev_dbg("%s has been deleted", ndev_name(vnet));
	mutex_lock(&bt_mng->bitmap_lock);
	err = bt_virnet_get_cdev_number(vnet, &number);
	if (likely(!err))
		bt_clear_bit(&bt_mng->bitmap, (u32)MINOR(number));
	bt_table_remove_device(bt_mng->devices_table, vnet);
	bt_virnet_destroy(vnet);
	mutex_unlock(&bt_mng->bitmap_lock);
	return OK;
}

static int bt_cmd_query_all_virnets(struct bt_drv *bt_mng, unsigned long arg)
{
	if (unlikely(put_user(bt_mng->bitmap, (u32 *)arg))) {
		btdev_dbg_err("put_user failed");
		return -EIO;
	}
	return OK;
}

static int bt_cmd_delete_all_virnets(struct bt_drv *bt_mng, unsigned long arg)
{
	return bt_table_delete_all(bt_mng);
}

static long bt_mng_file_ioctl(struct file *filep,
			      unsigned int cmd,
			      unsigned long arg)
{
	int ret;
	struct bt_drv *bt_mng = NULL;

	if (unlikely(!filep) || unlikely(!filep->private_data)) {
		btdev_dbg_err("invalid parameter");
		return -EINVAL;
	}
	bt_mng = filep->private_data;

	switch (cmd) {
	case BT_IOC_CREATE:
		ret = bt_cmd_create_virnet(bt_mng, arg);
		break;
	case BT_IOC_DELETE:
		ret = bt_cmd_delete_virnet(bt_mng, arg);
		break;
	case BT_IOC_QUERY_ALL:
		ret = bt_cmd_query_all_virnets(bt_mng, arg);
		break;
	case BT_IOC_DELETE_ALL:
		ret = bt_cmd_delete_all_virnets(bt_mng, arg);
		break;
	default:
		btdev_dbg_err("not a valid cmd(%u)", cmd);
		return -ENOIOCTLCMD;
	}
	return ret;
}

static const struct file_operations g_bt_mng_file_ops = {
	.owner = THIS_MODULE,
	.open = bt_mng_file_open,
	.release = bt_mng_file_release,
	.unlocked_ioctl = bt_mng_file_ioctl,
	.compat_ioctl = bt_mng_file_ioctl};

static netdev_tx_t bt_virnet_xmit(struct sk_buff *skb,
				  struct net_device *dev)
{
	int ret;
	struct bt_virnet *vnet = NULL;

	if (unlikely(!skb) || unlikely(!dev)) {
		btdev_dbg_err("invalid parameter");
		return -EINVAL;
	}

	vnet = bt_table_find(g_bt_drv->devices_table, dev->name);
	if (unlikely(!vnet)) {
		btdev_dbg_err("bt_table_find %s failed", ndev_name(vnet));
		return -EINVAL;
	}

	ret = bt_virnet_produce_data(vnet, (void *)skb);
	if (unlikely(ret < 0)) {
		btdev_dbg("%s produce data failed: ring is full, need to stop queue",
			  ndev_name(vnet));
		netif_stop_queue(vnet->ndev);
		return NETDEV_TX_BUSY;
	}

	vnet->ndev->stats.tx_packets++;
	vnet->ndev->stats.tx_bytes += skb->len;

	btdev_dbg("%s send success, skb-len=%u", ndev_name(vnet), skb->len);
	return NETDEV_TX_OK;
}

static const struct net_device_ops g_bt_virnet_ops = {
	.ndo_start_xmit = bt_virnet_xmit,
	.ndo_change_mtu = bt_virnet_change_mtu};

static struct bt_table *bt_table_init(void)
{
	struct bt_table *tbl = kmalloc(sizeof(*tbl), GFP_KERNEL);

	if (unlikely(!tbl)) {
		btdev_dbg_err("alloc failed");
		return NULL;
	}

	INIT_LIST_HEAD(&tbl->head);
	mutex_init(&tbl->tbl_lock);
	tbl->num = 0;
	return tbl;
}

static int bt_table_add_device(struct bt_table *tbl, struct bt_virnet *vn)
{
	struct bt_virnet *vnet = NULL;

	if (unlikely(!tbl)) {
		btdev_dbg_err("invalid parameter");
		return -EINVAL;
	}

	vnet = bt_table_find(tbl, ndev_name(vn));
	if (unlikely(vnet)) {
		btdev_dbg_err("found duplicated device %s", ndev_name(vn));
		return -ENOIOCTLCMD; // duplicated
	}

	btdev_dbg("%s has been added", ndev_name(vn));
	mutex_lock(&tbl->tbl_lock);
	list_add_tail(&vn->virnet_entry, &tbl->head);
	if (tbl->num < UINT32_MAX)
		++tbl->num;
	mutex_unlock(&tbl->tbl_lock);

	return OK;
}

static void bt_table_remove_device(struct bt_table *tbl, struct bt_virnet *vn)
{
	if (unlikely(!tbl))
		return;

	btdev_dbg("%s has been removed", ndev_name(vn));
	mutex_lock(&tbl->tbl_lock);
	list_del(&vn->virnet_entry);
	if (tbl->num)
		--tbl->num;
	mutex_unlock(&tbl->tbl_lock);
}

static struct bt_virnet *bt_table_find(struct bt_table *tbl, const char *ifa_name)
{
	struct bt_virnet *vnet = NULL;

	if (unlikely(!tbl) || unlikely(!ifa_name)) {
		btdev_dbg_err("invalid parameter");
		return NULL;
	}

	list_for_each_entry(vnet, &tbl->head, virnet_entry) {
		if (!strcmp(ndev_name(vnet), ifa_name))
			return vnet;
	}

	return NULL;
}

static void __bt_table_delete_all(struct bt_drv *drv)
{
	dev_t number;
	struct bt_virnet *vnet = NULL;
	struct bt_virnet *tmp_vnet = NULL;

	if (unlikely(!g_bt_drv->devices_table))
		return;

	list_for_each_entry_safe(vnet,
				 tmp_vnet,
				 &drv->devices_table->head,
				 virnet_entry) {
		int err = bt_virnet_get_cdev_number(vnet, &number);

		if (likely(!err))
			bt_clear_bit(&drv->bitmap, (u32)MINOR(number));
		list_del(&vnet->virnet_entry);
		btdev_dbg("%s has been deleted", ndev_name(vnet));
		bt_virnet_destroy(vnet);
	}
	drv->devices_table->num = 0;
}

static int bt_table_delete_all(struct bt_drv *drv)
{
	if (unlikely(!drv->devices_table))
		return -EINVAL;

	mutex_lock(&drv->bitmap_lock);
	mutex_lock(&drv->devices_table->tbl_lock);

	__bt_table_delete_all(drv);

	mutex_unlock(&drv->devices_table->tbl_lock);
	mutex_unlock(&drv->bitmap_lock);
	return OK;
}

static void bt_table_destroy(struct bt_drv *drv)
{
	__bt_table_delete_all(drv);
	kfree(drv->devices_table);
	drv->devices_table = NULL;
}

static struct bt_ring *__bt_ring_create(int size)
{
	struct bt_ring *ring;

	if (unlikely(size < 0))
		return NULL;

	ring = kmalloc(sizeof(*ring), GFP_KERNEL);
	if (unlikely(!ring)) {
		btdev_dbg_err("ring alloc failed");
		return NULL;
	}

	ring->head = 0;
	ring->tail = 0;
	ring->data = kmalloc_array(size, sizeof(void *), GFP_KERNEL);
	if (unlikely(!ring->data)) {
		btdev_dbg_err("ring data allocfailed");
		kfree(ring);
		return NULL;
	}
	ring->size = size;

	return ring;
}

static struct bt_ring *bt_ring_create(void)
{
	return __bt_ring_create(BT_RING_BUFFER_SIZE);
}

static int bt_ring_is_empty(const struct bt_ring *ring)
{
	if (unlikely(!ring))
		return TRUE;

	return ring->head == ring->tail;
}

static int bt_ring_is_full(const struct bt_ring *ring)
{
	if (unlikely(!ring))
		return TRUE;

	return (ring->head + 1) % ring->size == ring->tail;
}

static void bt_ring_produce(struct bt_ring *ring, void *data)
{
	smp_mb(); // Make sure the read and write order is correct
	if (likely(ring->head < ring->size)) {
		ring->data[ring->head] = data;
		ring->head = (ring->head + 1) % ring->size;
	}
	smp_wmb(); // Make sure the write order is correct
}

static void *bt_ring_current(struct bt_ring *ring)
{
	void *data = NULL;

	if (unlikely(!ring) || unlikely(ring->tail > ring->size))
		return data;

	data = ring->data[ring->tail];
	return data;
}

static void bt_ring_consume(struct bt_ring *ring)
{
	if (unlikely(!ring))
		return;

	smp_rmb(); // Make sure the read order is correct
	ring->tail = (ring->tail + 1) % ring->size;
	smp_mb(); // Make sure the read and write order is correct
}

static void bt_ring_destroy(struct bt_ring *ring)
{
	if (unlikely(!ring))
		return;

	kfree(ring->data);
	kfree(ring);
}

static int bt_virnet_produce_data(struct bt_virnet *dev, void *data)
{
	if (unlikely(bt_ring_is_full(dev->tx_ring))) {
		btdev_dbg("ring is full");
		return -ENFILE;
	}

	/* There is a memory barrier inside the function */
	bt_ring_produce(dev->tx_ring, data);
	wake_up(&dev->rx_queue);
	return OK;
}

/**
 * register all the region
 */
static int bt_cdev_region_init(int major, int count)
{
	return register_chrdev_region(MKDEV(major, 0), count, "bt");
}

static struct class *bt_dev_class_create(void)
{
	struct class *cls = class_create(THIS_MODULE, "bt");

	if (IS_ERR(cls)) {
		btdev_dbg_err("create struct class failed");
		return NULL;
	}
	return cls;
}

static void bt_dev_class_destroy(struct class *cls)
{
	if (unlikely(!cls))
		return;

	class_destroy(cls);
}

static void bt_cdev_device_destroy(struct bt_cdev *dev)
{
	device_destroy(dev->bt_class, dev->cdev->dev);
}

static int bt_cdev_device_create(struct bt_cdev *dev,
				 struct class *cls,
				 u32 id)
{
	struct device *device = NULL;
	dev_t devno = MKDEV(BT_DEV_MAJOR, id);
	int ret;

	if (unlikely(!cls)) {
		btdev_dbg_err("not a valid class");
		return -EINVAL;
	}

	dev->bt_class = cls;
	device = device_create(cls, NULL, devno, NULL, "%s%u", BT_DEV_NAME_PREFIX, id);
	if (IS_ERR(device)) {
		btdev_dbg_err("create device failed, id=%d", id);
		return -EIO;
	}
	ret = snprintf(dev->dev_filename, sizeof(dev->dev_filename),
		       "%s%u", BT_DEV_PATH_PREFIX, id);
	if (ret < 0) {
		btdev_dbg_err("snprintf failed, id=%d", id);
		bt_cdev_device_destroy(dev);
		return -EFAULT;
	}

	btdev_dbg("%s has been created", dev->dev_filename);
	return OK;
}

static struct bt_cdev *bt_cdev_create(const struct file_operations *ops,
				      u32 id)
{
	int ret;
	int minor = id;
	struct bt_cdev *dev = NULL;
	struct cdev *chrdev = NULL;

	dev = kmalloc(sizeof(*dev), GFP_KERNEL);
	if (unlikely(!dev)) {
		btdev_dbg_err("dev alloc failed, id=%d", id);
		goto dev_alloc_failed;
	}

	chrdev = cdev_alloc();
	if (unlikely(!chrdev)) {
		btdev_dbg_err("cdev alloc failed, id=%d", id);
		goto cdev_alloc_failed;
	}

	cdev_init(chrdev, ops);
	dev->cdev = chrdev;

	ret = cdev_add(chrdev, MKDEV(BT_DEV_MAJOR, minor), 1);
	if (unlikely(ret < 0)) {
		btdev_dbg_err("cdev add failed, id=%d", id);
		goto cdev_add_failed;
	}

	if (unlikely(bt_cdev_device_create(dev, g_bt_drv->bt_class, minor) < 0)) {
		btdev_dbg_err("bt cdev device create failed, id=%d", id);
		goto cdev_device_create_failed;
	}

	return dev;

cdev_device_create_failed:
cdev_add_failed:
	cdev_del(chrdev);

cdev_alloc_failed:
	kfree(dev);

dev_alloc_failed:
	return NULL;
}

/**
 * delete one char device
 */
static void bt_cdev_delete(struct bt_cdev *bt_cdev)
{
	dev_t devno;

	if (likely(bt_cdev)) {
		devno = bt_cdev->cdev->dev;

		/* BT_DEV_PATH_PREFIX + ID --> /dev/btdev1 */
		unregister_chrdev(MAJOR(devno), bt_cdev->dev_filename + strlen(BT_DEV_PATH_PREFIX));
		bt_cdev_device_destroy(bt_cdev);

		cdev_del(bt_cdev->cdev);
	} else {
		btdev_dbg_err("cdev is null");
	}
}

/**
 * create and add data char device
 */
static struct bt_io_file *bt_create_io_file(u32 id)
{
	struct bt_io_file *file = kmalloc(sizeof(*file), GFP_KERNEL);

	if (unlikely(!file)) {
		btdev_dbg_err("file alloc failed, id=%d", id);
		return NULL;
	}
	file->bt_cdev = bt_cdev_create(&g_bt_io_file_ops, id);
	if (unlikely(!file->bt_cdev)) {
		btdev_dbg_err("create cdev failed, id=%d", id);
		kfree(file);
		return NULL;
	}
	atomic_set(&file->read_open_limit, 1);
	atomic_set(&file->write_open_limit, 1);
	return file;
}

static struct bt_io_file **bt_create_io_files(void)
{
	int i;
	struct bt_io_file **all_files = kmalloc(BT_VIRNET_MAX_NUM * sizeof(struct bt_io_file *),
						GFP_KERNEL);

	if (unlikely(!all_files)) {
		btdev_dbg_err("all_files alloc failed");
		return NULL;
	}
	for (i = 0; i < BT_VIRNET_MAX_NUM; ++i)
		all_files[i] = bt_create_io_file(i + 1);

	return all_files;
}

static void bt_delete_io_file(struct bt_io_file *file)
{
	if (unlikely(!file))
		return;

	bt_cdev_delete(file->bt_cdev);
	kfree(file);
}

static void bt_delete_io_files(struct bt_drv *bt_mng)
{
	int i;

	for (i = 0; i < BT_VIRNET_MAX_NUM; ++i)
		bt_delete_io_file(bt_mng->io_files[i]);

	kfree(bt_mng->io_files);
	bt_mng->io_files = NULL;
}

/**
 * create and add management char device
 */
static struct bt_mng_file *bt_create_mng_file(int id)
{
	struct bt_mng_file *file = kmalloc(sizeof(*file), GFP_KERNEL);

	if (unlikely(!file)) {
		btdev_dbg_err("file alloc failed");
		return NULL;
	}

	file->bt_cdev = bt_cdev_create(&g_bt_mng_file_ops, id);
	if (unlikely(!file->bt_cdev)) {
		btdev_dbg_err("create cdev failed");
		kfree(file);
		return NULL;
	}

	atomic_set(&file->open_limit, 1);

	btdev_dbg("mng file has been created");
	return file;
}

static void bt_delete_mng_file(struct bt_mng_file *file)
{
	if (unlikely(!file))
		return;

	bt_cdev_delete(file->bt_cdev);
	kfree(file);
}

/**
 * unregister the region
 */
static void bt_cdev_region_destroy(int major, int count)
{
	return unregister_chrdev_region(MKDEV(major, 0), count);
}

/**
 * create one net device
 */
static struct net_device *bt_net_device_create(u32 id)
{
	struct net_device *ndev = NULL;
	int err;
	char ifa_name[IFNAMSIZ];

	if (unlikely(id < 0) || unlikely(id > BT_VIRNET_MAX_NUM)) {
		btdev_dbg_err("invalid id");
		return NULL;
	}
	err = snprintf(ifa_name, sizeof(ifa_name), "%s%d", BT_VIRNET_NAME_PREFIX, id);
	if (err < 0) {
		btdev_dbg_err("snprintf failed, id=%d", id);
		return NULL;
	}
	ndev = alloc_netdev(0, ifa_name, NET_NAME_UNKNOWN, ether_setup);
	if (unlikely(!ndev)) {
		btdev_dbg_err("%s ndev alloc failed", ifa_name);
		return NULL;
	}

	ndev->netdev_ops = &g_bt_virnet_ops;
	ndev->flags |= IFF_NOARP;
	ndev->flags &= ~IFF_BROADCAST & ~IFF_MULTICAST;
	ndev->min_mtu = 1;
	ndev->max_mtu = ETH_MAX_MTU;

	err = register_netdev(ndev);
	if (unlikely(err)) {
		btdev_dbg_err("%s register netdev failed", ifa_name);
		free_netdev(ndev);
		return NULL;
	}

	btdev_dbg("%s has been created", ifa_name);
	return ndev;
}

/**
 * destroy one net device
 */
static void bt_net_device_destroy(struct net_device *dev)
{
	btdev_dbg("%s has been destroyed", dev->name);
	unregister_netdev(dev);
	free_netdev(dev);
}

static struct bt_io_file *bt_get_io_file(struct bt_drv *drv, int id)
{
	if (id >= 1 && id <= BT_VIRNET_MAX_NUM)
		return drv->io_files[id - 1];

	return NULL;
}

/**
 * create an virtual net_device
 */
static struct bt_virnet *bt_virnet_create(struct bt_drv *bt_mng, u32 id)
{
	struct bt_virnet *vnet = kmalloc(sizeof(*vnet), GFP_KERNEL);

	if (unlikely(!vnet)) {
		btdev_dbg_err("invalid parameter");
		goto out_of_memory;
	}

	vnet->tx_ring = bt_ring_create();
	if (unlikely(!vnet->tx_ring)) {
		btdev_dbg_err("create ring failed");
		goto bt_ring_create_failed;
	}

	vnet->ndev = bt_net_device_create(id);
	if (unlikely(!vnet->ndev)) {
		btdev_dbg_err("create net device failed");
		goto net_device_create_failed;
	}

	vnet->io_file = bt_get_io_file(bt_mng, id);
	if (unlikely(!vnet->io_file)) {
		btdev_dbg_err("create cdev failed");
		goto get_io_file_failed;
	}

	init_waitqueue_head(&vnet->rx_queue);

	set_state(vnet, BT_VIRNET_STATE_CREATED);
	btdev_dbg("%s has been created", cdev_name(vnet));
	return vnet;

get_io_file_failed:
	bt_net_device_destroy(vnet->ndev);

net_device_create_failed:
	bt_ring_destroy(vnet->tx_ring);

bt_ring_create_failed:
	kfree(vnet);

out_of_memory:
	return NULL;
}

static void bt_virnet_destroy(struct bt_virnet *vnet)
{
	btdev_dbg("%s has been destroyed", ndev_name(vnet));
	bt_ring_destroy(vnet->tx_ring);
	bt_net_device_destroy(vnet->ndev);

	set_state(vnet, BT_VIRNET_STATE_DELETED);

	kfree(vnet);
}

static void __exit bt_module_release(void)
{
	if (likely(g_bt_drv)) {
		bt_table_destroy(g_bt_drv);
		bt_delete_io_files(g_bt_drv);
		bt_delete_mng_file(g_bt_drv->mng_file);
		bt_dev_class_destroy(g_bt_drv->bt_class);

		kfree(g_bt_drv);
		g_bt_drv = NULL;
	}

	bt_cdev_region_destroy(BT_DEV_MAJOR, BT_VIRNET_MAX_NUM);
	remove_proc_entry("bt_info_proc", NULL);
	btdev_dbg("success");
}

static int __bt_module_base_init(void)
{
	int ret = 0;

	g_bt_drv = kmalloc(sizeof(*g_bt_drv), GFP_KERNEL);
	if (unlikely(!g_bt_drv)) {
		btdev_dbg_err("bt_drv alloc failed");
		ret = -ENOMEM;
		goto btdrv_alloc_failed;
	}

	if (unlikely(bt_cdev_region_init(BT_DEV_MAJOR, BT_VIRNET_MAX_NUM) < 0)) {
		btdev_dbg_err("bt cdev region init failed");
		ret = -EFAULT;
		goto cdev_region_fail;
	}

	g_bt_drv->devices_table = bt_table_init();
	if (unlikely(!g_bt_drv->devices_table)) {
		btdev_dbg_err("bt table init failed");
		ret = -ENOMEM;
		goto table_init_fail;
	}

	g_bt_drv->bt_class = bt_dev_class_create();
	if (unlikely(!g_bt_drv->bt_class)) {
		btdev_dbg_err("class create failed");
		ret = -ENOMEM;
		goto class_create_fail;
	}

	g_bt_drv->io_files = bt_create_io_files();
	if (unlikely(!g_bt_drv->io_files)) {
		btdev_dbg_err("bt create io files failed");
		ret = -ENOMEM;
		goto io_files_create_fail;
	}

	mutex_init(&g_bt_drv->bitmap_lock);
	g_bt_drv->bitmap = 0;
	return ret;

io_files_create_fail:
	bt_dev_class_destroy(g_bt_drv->bt_class);

class_create_fail:
	bt_table_destroy(g_bt_drv);

table_init_fail:
	bt_cdev_region_destroy(BT_DEV_MAJOR, BT_VIRNET_MAX_NUM);

cdev_region_fail:
	kfree(g_bt_drv);
	g_bt_drv = NULL;

btdrv_alloc_failed:
	return ret;
}

static int __bt_module_dev_create(void)
{
	int mid = 0;
	struct proc_dir_entry *entry = NULL;
	int ret = 0;

	mutex_lock(&g_bt_drv->bitmap_lock);
	g_bt_drv->mng_file = bt_create_mng_file(mid);
	if (unlikely(!g_bt_drv->mng_file)) {
		btdev_dbg_err("bt create mng file failed");
		ret = -ENOMEM;
		mutex_unlock(&g_bt_drv->bitmap_lock);
		goto mng_file_create_fail;
	}
	bt_set_bit(&g_bt_drv->bitmap, mid);
	mutex_unlock(&g_bt_drv->bitmap_lock);

	entry = proc_create_data("bt_info_proc", 0, NULL, &g_bt_proc_fops, NULL);
	if (unlikely(!entry)) {
		btdev_dbg_err("create proc data failed");
		ret = -ENOMEM;
		goto proc_create_fail;
	}

	return ret;
proc_create_fail:
	bt_delete_mng_file(g_bt_drv->mng_file);

mng_file_create_fail:
	bt_delete_io_files(g_bt_drv);
	bt_dev_class_destroy(g_bt_drv->bt_class);
	bt_table_destroy(g_bt_drv);
	bt_cdev_region_destroy(BT_DEV_MAJOR, BT_VIRNET_MAX_NUM);
	kfree(g_bt_drv);
	g_bt_drv = NULL;

	return ret;
}

/**
 *  module init function
 */
static int __init bt_module_init(void)
{
	int ret;

	ret = __bt_module_base_init();
	if (ret < 0)
		return ret;

	return __bt_module_dev_create();
}

module_init(bt_module_init);
module_exit(bt_module_release);
MODULE_LICENSE("GPL");
