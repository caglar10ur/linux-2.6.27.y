/*
 *  TUN - Universal TUN/TAP device driver.
 *  Copyright (C) 1999-2002 Maxim Krasnyansky <maxk@qualcomm.com>
 *  Modifications for PlanetLab by
 *  Mark Huang <mlhuang@cs.princeton.edu>
 *  Copyright (C) 2005 The Trustees of Princeton University
 *  Ported to PlanetLab 4.2 by Sapan Bhatia <sapanb@cs.princeton.edu>
 *
 *  Modifications for PlanetLab by
 *  Mark Huang <mlhuang@cs.princeton.edu>
 *  Copyright (C) 2005 The Trustees of Princeton University
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 *  $Id: vnet_tun.c,v 1.10 2007/03/07 21:25:26 mef Exp $
 */

/*
 *  Daniel Podlejski <underley@underley.eu.org>
 *    Modifications for 2.3.99-pre5 kernel.
 */

#define TUN_VER "1.5"

int vnet_verbose=1;

#define dbg(format, args...) do { if (vnet_verbose >= 2) { printk(format, ## args); } } while (0)
#define err(format, args...) do { if (vnet_verbose >= 1) { printk(format, ## args); } } while (0)

#include <linux/version.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/major.h>
#include <linux/slab.h>
#include <linux/poll.h>
#include <linux/fcntl.h>
#include <linux/init.h>
#include <linux/random.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/miscdevice.h>
#include <linux/rtnetlink.h>
#include <linux/if.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_tun.h>
#include <net/sock.h>

#include <asm/system.h>
#include <asm/uaccess.h>

/*
 * PlanetLab TAP device
 *
 * A single, persistent tap0 to /dev/net/tun tunnel. Packets sent out
 * the tap0 device, via either IP or raw sockets, are queued to both
 * the sending slice's /dev/net/tun queue, and the root queue. Only
 * one reader of each queue is allowed at a time. Any type of packet
 * may be written to /dev/net/tun and received via packet socket(s)
 * bound to tap0. However, only locally destined IP packets will be
 * injected into the stack, and such packets are subject to the same
 * connection tracking and ownership assignment that all inbound IP
 * packets are subject to.
 */

struct net_device tun_netdev;
static struct net_device_stats tun_stats;

int print_once=1;

static inline xid_t
get_sk_xid(struct sock *sk)
{
	if (sk) {
		return (int) sk->sk_nid >= 0 ? sk->sk_nid : 0;
	} 
	else {
		if (in_interrupt() && print_once) {
			print_once=0;
			printk(KERN_EMERG "vnet_tun: get-sk_xid called in interrupt context! Stephen: Don't Panic.\n");
		}
		return current->xid;
	}
}

#define set_sk_xid(sk,xid) sk->sk_nid=xid
#define set_skb_xid(skb,xid) skb->skb_tag=xid
#define get_skb_xid(skb) skb->skb_tag

/* Extended fields */
struct tun_pi_ext {
	unsigned long mark;
	long timestamp_sec;
	long timestamp_usec;
};
#define TUN_PKT_EXT	0x0002
	
#include <net/ip.h>

/* UID hash function stolen from kernel/user.c */
#define XIDHASH_BITS		8
#define XIDHASH_SZ		(1 << XIDHASH_BITS)
#define XIDHASH_MASK		(XIDHASH_SZ - 1)
#define __xidhashfn(xid)	(((xid >> XIDHASH_BITS) + xid) & XIDHASH_MASK)

static struct list_head tun_dev_hash[XIDHASH_SZ];
static rwlock_t tun_dev_hash_lock = RW_LOCK_UNLOCKED;

static inline xid_t
get_file_xid(struct file *file)
{
	        return file->f_xid;
}

static inline void
set_file_xid(struct file *file, xid_t xid)
{
	        file->f_xid = xid;
}

static struct tun_struct *tun_get_by_xid(xid_t xid)
{
	struct tun_struct *tun;

	read_lock_bh(&tun_dev_hash_lock);

	list_for_each_entry(tun, &tun_dev_hash[__xidhashfn(xid)], list) {
		if (tun->owner == xid) {
			read_unlock_bh(&tun_dev_hash_lock);
			return tun;
		}
	}

	read_unlock_bh(&tun_dev_hash_lock);

	return NULL;
}

/* Network device part of the driver */

static void tun_xmit(struct sk_buff *skb, struct tun_struct *tun)
{
	/* Drop packet if interface is not attached */
	if (!tun || !tun->attached)
		goto drop;

	dbg("%s:%d: tun_xmit %d\n", tun->dev->name, tun->owner, skb->len);

	/* Queue packet */
	if (skb_queue_len(&tun->readq) >= tun->dev->tx_queue_len)
		goto drop;

	skb = skb_clone(skb, GFP_ATOMIC);
	if (!skb)
		goto drop;

	skb_queue_tail(&tun->readq, skb);

	/* Notify and wake up reader process */
	if (tun->flags & TUN_FASYNC)
		kill_fasync(&tun->fasync, SIGIO, POLL_IN);
	wake_up_interruptible(&tun->read_wait);

 drop:
	if (tun)
		tun->stats.tx_dropped++;
	tun_stats.tx_dropped++;
}

/* Net device start xmit */
static int tun_net_xmit(struct sk_buff *skb, struct net_device *dev)
{
	xid_t xid, skb_xid; 
	struct tun_struct *tun;
	skb_xid=get_skb_xid(skb);
	if (skb_xid<1) 
		xid=get_sk_xid(skb->sk);
	else
		xid=skb_xid;

	tun = tun_get_by_xid(xid);
	/* Mark packet */
	set_skb_xid(skb, xid);

	tun_xmit(skb, tun);

	/* Copy root on packets that the slice is not listening for */
	if ((!tun || !tun->attached) && xid) {
		tun = tun_get_by_xid(0);
		tun_xmit(skb, tun);
	}

	kfree_skb(skb);
	return 0;
}

static void tun_net_mclist(struct net_device *dev)
{
	/* Nothing to do for multicast filters. 
	 * We always accept all frames. */
	return;
}

static struct net_device_stats *tun_net_stats(struct net_device *dev)
{
	struct tun_struct *tun = tun_get_by_xid(current->xid);
	return tun ? &tun->stats : &tun_stats;
}

/* Character device part */

/* Poll */
static unsigned int tun_chr_poll(struct file *file, poll_table * wait)
{  
	struct tun_struct *tun = file->private_data;
	unsigned int mask = POLLOUT | POLLWRNORM;

	if (!tun)
		return -EBADFD;

	dbg("%s:%d: tun_chr_poll\n", tun->dev->name, tun->owner);

	poll_wait(file, &tun->read_wait, wait);
 
	if (skb_queue_len(&tun->readq))
		mask |= POLLIN | POLLRDNORM;

	return mask;
}

/* Get packet from user space buffer */
static __inline__ ssize_t tun_get_user(struct tun_struct *tun, struct iovec *iv, size_t count)
{
	struct tun_pi pi = { 0, __constant_htons(ETH_P_IP) };
	struct tun_pi_ext pi_ext;
	struct sk_buff *skb;
	size_t len = count;

	if (!(tun->flags & TUN_NO_PI)) {
		if ((len -= sizeof(pi)) < 0)
			return -EINVAL;

		if(memcpy_fromiovec((void *)&pi, iv, sizeof(pi)))
			return -EFAULT;

		if (pi.flags & TUN_PKT_EXT) {
			if ((len -= sizeof(pi_ext)) < 0)
				return -EINVAL;

			if (memcpy_fromiovec((void *)&pi_ext, iv, sizeof(pi_ext)))
				return -EFAULT;
		}
	}
 
	if (!(skb = alloc_skb(len + 2, GFP_KERNEL))) {
		tun->stats.rx_dropped++;
		tun_stats.rx_dropped++;
		return -ENOMEM;
	}

	skb_reserve(skb, 2);
	if (memcpy_fromiovec(skb_put(skb, len), iv, len))
		return -EFAULT;

	skb->dev = tun->dev;
	switch (tun->flags & TUN_TYPE_MASK) {
	case TUN_TUN_DEV:
		skb_reset_mac_header(skb);
		skb->protocol = pi.proto;
		break;
	case TUN_TAP_DEV:
		skb->protocol = eth_type_trans(skb, tun->dev);
		break;
	};

	if (tun->flags & TUN_NOCHECKSUM)
		skb->ip_summed = CHECKSUM_UNNECESSARY;

	/* Mark packet */
	set_skb_xid(skb, tun->owner);

	netif_rx_ni(skb);
   
	tun->stats.rx_packets++;
	tun->stats.rx_bytes += len;
	tun_stats.rx_packets++;
	tun_stats.rx_bytes += len;

	return count;
} 

static inline size_t iov_total(const struct iovec *iv, unsigned long count)
{
	unsigned long i;
	size_t len;

	for (i = 0, len = 0; i < count; i++) 
		len += iv[i].iov_len;

	return len;
}

/* Writev - Obsolete in 2.6.22, but let's keep this aroudn just in case */
static ssize_t tun_chr_writev(struct file * file, const struct iovec *iv, 
			      unsigned long count, loff_t *pos)
{
	struct tun_struct *tun = file->private_data;

	if (!tun)
		return -EBADFD;

	dbg("%s:%d: tun_chr_write %ld\n", tun->dev->name, tun->owner, count);

	return tun_get_user(tun, (struct iovec *) iv, iov_total(iv, count));
}

/* Write */
static ssize_t tun_chr_write(struct file * file, const char __user * buf, 
			     size_t count, loff_t *pos)
{
	struct iovec iv = { (void __user *) buf, count };
	return tun_chr_writev(file, &iv, 1, pos);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,14)

static inline void skb_get_timestamp(const struct sk_buff *skb, struct timeval *stamp)
{
	stamp->tv_sec = skb->stamp.tv_sec;
	stamp->tv_usec = skb->stamp.tv_usec;
}

static inline void skb_set_timestamp(struct sk_buff *skb, const struct timeval *stamp)
{
	skb->stamp.tv_sec = stamp->tv_sec;
	skb->stamp.tv_usec = stamp->tv_usec;
}

static void __net_timestamp(struct sk_buff *skb)
{
	struct timeval tv;

	do_gettimeofday(&tv);
	skb_set_timestamp(skb, &tv);
}

#endif

/* Put packet to the user space buffer */
static __inline__ ssize_t tun_put_user(struct tun_struct *tun,
				       struct sk_buff *skb,
				       struct iovec *iv, int len)
{
	struct tun_pi pi;
	struct tun_pi_ext pi_ext;
	struct timeval stamp;
	ssize_t total = 0;

	if (!(tun->flags & TUN_NO_PI)) {
		struct iovec iv1 = { iv->iov_base, iv->iov_len };

		if ((len -= sizeof(pi)) < 0)
			return -EINVAL;

		if (memcpy_fromiovec((void *)&pi, &iv1, sizeof(pi)))
			return -EFAULT;

		if (pi.flags & TUN_PKT_EXT) {
			if ((len -= sizeof(pi_ext)) < 0)
				return -EINVAL;

			/* We might not have a timestamp, get one */
			skb_get_timestamp(skb, &stamp);
			if (stamp.tv_sec == 0) {
				__net_timestamp(skb);
				skb_get_timestamp(skb, &stamp);
			}

			pi.flags = TUN_PKT_EXT;
			pi.proto = skb->protocol;
			pi_ext.timestamp_sec = stamp.tv_sec;
			pi_ext.timestamp_usec = stamp.tv_usec;
			pi_ext.mark = skb->skb_tag;
		} else {
			pi.flags = 0;
			pi.proto = skb->protocol;
		}

		if (len < skb->len) {
			/* Packet will be striped */
			pi.flags |= TUN_PKT_STRIP;
		}
 
		if (memcpy_toiovec(iv, (void *) &pi, sizeof(pi)))
			return -EFAULT;
		total += sizeof(pi);

		if (pi.flags & TUN_PKT_EXT) {
			if (memcpy_toiovec(iv, (void *) &pi_ext, sizeof(pi_ext)))
				return -EFAULT;
			total += sizeof(pi_ext);
		}
	}       

	len = min_t(int, skb->len, len);

	skb_copy_datagram_iovec(skb, 0, iv, len);
	total += len;

	tun->stats.tx_packets++;
	tun->stats.tx_bytes += len;
	tun_stats.tx_packets++;
	tun_stats.tx_bytes += len;

	return total;
}

/* Readv - Obsolete in 2.6.22, but let's keep this aroudn just in case */
static ssize_t tun_chr_readv(struct file *file, const struct iovec *iv,
			    unsigned long count, loff_t *pos)
{
	struct tun_struct *tun = file->private_data;
	DECLARE_WAITQUEUE(wait, current);
	struct sk_buff *skb;
	ssize_t len, ret = 0;

	if (!tun)
		return -EBADFD;

	dbg("%s:%d: tun_chr_read\n", tun->dev->name, tun->owner);

	len = iov_total(iv, count);
	if (len < 0)
		return -EINVAL;

	add_wait_queue(&tun->read_wait, &wait);
	while (len) {
		current->state = TASK_INTERRUPTIBLE;

		/* Read frames from the queue */
		if (!(skb=skb_dequeue(&tun->readq))) {
			if (file->f_flags & O_NONBLOCK) {
				ret = -EAGAIN;
				break;
			}
			if (signal_pending(current)) {
				ret = -ERESTARTSYS;
				break;
			}

			/* Nothing to read, let's sleep */
			schedule();
			continue;
		}

		ret = tun_put_user(tun, skb, (struct iovec *) iv, len);

		kfree_skb(skb);
		break;
	}

	current->state = TASK_RUNNING;
	remove_wait_queue(&tun->read_wait, &wait);

	return ret;
}

/* Read */
static ssize_t tun_chr_read(struct file * file, char __user * buf, 
			    size_t count, loff_t *pos)
{
	struct iovec iv = { buf, count };
	return tun_chr_readv(file, &iv, 1, pos);
}

static int tun_set_iff(struct file *file, struct ifreq *ifr)
{
	struct tun_struct *tun;

	tun = tun_get_by_xid(get_file_xid(file));
	if (tun) {
		if (tun->attached)
			return -EBUSY;

		/* Check permissions */
		if (tun->owner != -1 &&
		    get_file_xid(file) != tun->owner && !capable(CAP_NET_ADMIN))
			return -EPERM;
	}
	else {
		/* Create a new queue */
		tun = kmalloc(sizeof(struct tun_struct), GFP_KERNEL);
		if (!tun)
			return -ENOMEM;
		memset(tun, 0, sizeof(struct tun_struct));

		tun->dev = &tun_netdev;

		skb_queue_head_init(&tun->readq);
		init_waitqueue_head(&tun->read_wait);

		tun->owner = get_file_xid(file);

		write_lock_bh(&tun_dev_hash_lock);
		list_add(&tun->list, &tun_dev_hash[__xidhashfn(get_file_xid(file))]);
		write_unlock_bh(&tun_dev_hash_lock);
	}

	dbg("%s:%d: tun_set_iff\n", tun->dev->name, tun->owner);

	tun->flags = TUN_TAP_DEV;

	if (ifr->ifr_flags & IFF_NO_PI)
		tun->flags |= TUN_NO_PI;

	file->private_data = tun;
	tun->attached = 1;

	strcpy(ifr->ifr_name, tun->dev->name);
	return 0;
}

static int tun_chr_ioctl(struct inode *inode, struct file *file, 
			 unsigned int cmd, unsigned long arg)
{
	struct tun_struct *tun = file->private_data;

	if (cmd == TUNSETIFF && !tun) {
		struct ifreq ifr;
		int err;

		if (copy_from_user(&ifr, (void __user *)arg, sizeof(ifr)))
			return -EFAULT;
		ifr.ifr_name[IFNAMSIZ-1] = '\0';

		err = tun_set_iff(file, &ifr);

		if (err)
			return err;

		if (copy_to_user((void __user *)arg, &ifr, sizeof(ifr)))
			return -EFAULT;
		return 0;
	}

	if (!tun)
		return -EBADFD;

	dbg("%s:%d: tun_chr_ioctl cmd %d\n", tun->dev->name, tun->owner, cmd);

	switch (cmd) {
	case TUNSETNOCSUM:
		/* Disable/Enable checksum */
		if (arg)
			tun->flags |= TUN_NOCHECKSUM;
		else
			tun->flags &= ~TUN_NOCHECKSUM;

		dbg("%s:%d: checksum %s\n",
		    tun->dev->name, tun->owner, arg ? "disabled" : "enabled");
		break;

	case TUNSETPERSIST:
	case TUNSETOWNER:
	case TUNSETDEBUG:
		/* Not applicable */
		break;

	default:
		return -EINVAL;
	};

	return 0;
}

static int tun_chr_fasync(int fd, struct file *file, int on)
{
	struct tun_struct *tun = file->private_data;
	int ret;

	if (!tun)
		return -EBADFD;

	dbg("%s:%d: tun_chr_fasync %d\n", tun->dev->name, tun->owner, on);

	if ((ret = fasync_helper(fd, file, on, &tun->fasync)) < 0)
		return ret; 
 
	if (on) {
		ret = f_setown(file, current->pid, 0);
		if (ret)
			return ret;
		tun->flags |= TUN_FASYNC;
	} else 
		tun->flags &= ~TUN_FASYNC;

	return 0;
}

static int tun_chr_open(struct inode *inode, struct file * file)
{
	dbg("tunX: tun_chr_open\n");
	file->private_data = NULL;
	return 0;
}

static int tun_chr_close(struct inode *inode, struct file *file)
{
	struct tun_struct *tun = file->private_data;

	if (!tun)
		return 0;

	dbg("%s:%d: tun_chr_close\n", tun->dev->name, tun->owner);

	tun_chr_fasync(-1, file, 0);

	/* Detach from net device */
	file->private_data = NULL;
	tun->attached = 0;

	/* Drop read queue */
	skb_queue_purge(&tun->readq);

	return 0;
}

static struct file_operations tun_fops = {
	.owner	= THIS_MODULE,	
	.llseek = no_llseek,
	.read	= tun_chr_read,
	//.readv	= tun_chr_readv,
	.write	= tun_chr_write,
	//.writev = tun_chr_writev,
	.poll	= tun_chr_poll,
	.ioctl	= tun_chr_ioctl,
	.open	= tun_chr_open,
	.release = tun_chr_close,
	.fasync = tun_chr_fasync		
};

static struct miscdevice tun_miscdev = {
	.minor = TUN_MINOR,
	.name = "tun",
	.fops = &tun_fops,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18)
	.devfs_name = "net/tun",
#endif
};

int __init tun_init(void)
{
	int ret = 0;
	struct net_device *dev = &tun_netdev;
	int i;

	/* Initialize hash table */
	for (i = 0; i < XIDHASH_SZ; i++)
		INIT_LIST_HEAD(&tun_dev_hash[i]);

	ret = misc_register(&tun_miscdev);
	if (ret) {
		err("tun: Can't register misc device %d\n", TUN_MINOR);
		return ret;
	}

	memset(dev, 0, sizeof(struct net_device));

	/* Ethernet TAP Device */
	dev->set_multicast_list = tun_net_mclist;

	/* Generate random Ethernet address.  */
	*(u16 *)dev->dev_addr = htons(0x00FF);
	get_random_bytes(dev->dev_addr + sizeof(u16), 4);

	ether_setup(dev);

	dev->flags |= IFF_NOARP | IFF_POINTOPOINT;
	dev->flags &= ~IFF_MULTICAST;

	SET_MODULE_OWNER(dev);
	dev->hard_start_xmit = tun_net_xmit;
	dev->get_stats = tun_net_stats;

	strcpy(dev->name, "tap0");

	ret = register_netdev(dev);
	if (ret < 0)
		misc_deregister(&tun_miscdev);

	return ret;
}

void __exit tun_cleanup(void)
{
	struct tun_struct *tun, *nxt;
	int i;

	misc_deregister(&tun_miscdev);  

	write_lock_bh(&tun_dev_hash_lock);
	for (i = 0; i < XIDHASH_SZ; i++) {
		list_for_each_entry_safe(tun, nxt, &tun_dev_hash[i], list) {
			skb_queue_purge(&tun->readq);
			kfree(tun);
		}
	}
	write_unlock_bh(&tun_dev_hash_lock);

	unregister_netdev(&tun_netdev);
}

module_init(tun_init);
module_cleanup(tun_cleanup);
MODULE_LICENSE("GPL");
