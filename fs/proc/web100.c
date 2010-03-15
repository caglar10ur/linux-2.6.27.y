/*  
 *  fs/proc/web100.c
 *  
 * Copyright (C) 2001 Matt Mathis <mathis@psc.edu>
 * Copyright (C) 2001 John Heffner <jheffner@psc.edu>
 *
 * The Web 100 project.  See http://www.web100.org
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <linux/proc_fs.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <net/web100.h>
#include <linux/init.h>
#include <linux/sysctl.h>
#include <linux/mount.h>

#define WEB100MIB_BLOCK_SIZE	PAGE_SIZE - 1024

extern __u32 sysctl_wmem_default;
extern __u32 sysctl_wmem_max;

struct proc_dir_entry *proc_web100_dir;
static struct proc_dir_entry *proc_web100_header;


/*
 * Web100 variable reading/writing
 */

enum web100_connection_inos {
	PROC_CONN_SPEC_ASCII = 1,
	PROC_CONN_SPEC,
	PROC_CONN_READ,
	PROC_CONN_TEST,
	PROC_CONN_TUNE,
	PROC_CONN_HIGH_INO		/* Keep at the end */
};

enum {
	WEB100_TYPE_INTEGER = 0,
	WEB100_TYPE_INTEGER32,
	WEB100_TYPE_INET_ADDRESS_IPV4,
	WEB100_TYPE_IP_ADDRESS = WEB100_TYPE_INET_ADDRESS_IPV4, /* Depricated */
	WEB100_TYPE_COUNTER32,
	WEB100_TYPE_GAUGE32,
	WEB100_TYPE_UNSIGNED32,
	WEB100_TYPE_TIME_TICKS,
	WEB100_TYPE_COUNTER64,
	WEB100_TYPE_INET_PORT_NUMBER,
	WEB100_TYPE_UNSIGNED16 = WEB100_TYPE_INET_PORT_NUMBER, /* Depricated */
	WEB100_TYPE_INET_ADDRESS,
	WEB100_TYPE_INET_ADDRESS_IPV6,
};

struct web100_var;
typedef int (*web100_rwfunc_t)(void *buf, struct web100stats *stats,
			       struct web100_var *vp);

/* The printed variable description should look something like this (in ASCII):
 * varname offset type
 * where offset is the offset into the file.
 */
struct web100_var {
	char *name;
	__u32 type;
	int len;
	
	web100_rwfunc_t read;
	unsigned long read_data;	/* read handler-specific data */
	
	web100_rwfunc_t write;
	unsigned long write_data;	/* write handler-specific data */
	
	struct web100_var *next;
};

struct web100_file {
	int len;
	char *name;
	int low_ino;
	mode_t mode;
	
	struct web100_var *first_var;
};

#define F(name,ino,perm) { sizeof (name) - 1, (name), (ino), (perm), NULL }
static struct web100_file web100_file_arr[] = {
	F("spec-ascii", PROC_CONN_SPEC_ASCII, S_IFREG | S_IRUGO),
	F("spec", PROC_CONN_SPEC, S_IFREG | S_IRUGO),
	F("read", PROC_CONN_READ, 0),
	F("test", PROC_CONN_TEST, 0),
	F("tune", PROC_CONN_TUNE, 0),
	F(NULL, 0, 0) };
#undef F
#define WEB100_FILE_ARR_SIZE	(sizeof (web100_file_arr) / sizeof (struct web100_file))

/* This works only if the array is built in the correct order. */
static inline struct web100_file *web100_file_lookup(int ino) {
	return &web100_file_arr[ino - 1];
}

static void add_var(struct web100_file *file, char *name, int type,
	web100_rwfunc_t read, unsigned long read_data,
	web100_rwfunc_t write, unsigned long write_data)
{
	struct web100_var *var;
	
	/* Again, assuming add_var is only called at init. */
	if ((var = kmalloc(sizeof (struct web100_var), GFP_KERNEL)) == NULL)
		panic("No memory available for Web100 var.\n");
	
	var->name = name;
	var->type = type;
	switch (type) {
	case WEB100_TYPE_INET_PORT_NUMBER:
		var->len = 2;
		break;
	case WEB100_TYPE_INTEGER:
	case WEB100_TYPE_INTEGER32:
	case WEB100_TYPE_COUNTER32:
	case WEB100_TYPE_GAUGE32:
	case WEB100_TYPE_UNSIGNED32:
	case WEB100_TYPE_TIME_TICKS:
		var->len = 4;
		break;
	case WEB100_TYPE_COUNTER64:
		var->len = 8;
		break;
	case WEB100_TYPE_INET_ADDRESS:
		var->len = 17;
		break;
	default:
		printk("Web100: Warning: Adding variable of unknown type.\n");
		var->len = 0;
	}
	
	var->read = read;
	var->read_data = read_data;
	
	var->write = write;
	var->write_data = write_data;
	
	var->next = file->first_var;
	file->first_var = var;
}


/*
 * proc filesystem routines
 */

static struct inode *proc_web100_make_inode(struct super_block *sb, int ino)
{
	struct inode *inode;
	
	inode = new_inode(sb);
	if (!inode)
		goto out;
	
	inode->i_mtime = inode->i_atime = inode->i_ctime = CURRENT_TIME;
	inode->i_ino = ino;
	
	inode->i_uid = 0;
	inode->i_gid = 0;

out:
	return inode;
}

static inline ino_t ino_from_cid(int cid)
{
	return (cid << 8) | 0x80000000;
}

static inline ino_t ino_from_parts(ino_t dir_ino, __u16 low_ino)
{
	return (dir_ino & ~0xff) | low_ino;
}

static inline int cid_from_ino(ino_t ino)
{
	return (ino & 0x7fffff00) >> 8;
}

static inline int low_from_ino(ino_t ino)
{
	return ino & 0xff;
}

static int connection_file_open(struct inode *inode, struct file *file)
{
	int cid = cid_from_ino(inode->i_ino);
	struct web100stats *stats;
	
	read_lock_bh(&web100_linkage_lock);
	stats = web100stats_lookup(cid);
	if (stats == NULL || stats->wc_dead) {
		read_unlock_bh(&web100_linkage_lock);
		return -ENOENT;
	}
	web100_stats_use(stats);
	read_unlock_bh(&web100_linkage_lock);
	
	return 0;
}

static int connection_file_release(struct inode *inode, struct file *file)
{
	int cid = cid_from_ino(inode->i_ino);
	struct web100stats *stats;
	
	read_lock_bh(&web100_linkage_lock);
	stats = web100stats_lookup(cid);
	if (stats == NULL) {
		read_unlock_bh(&web100_linkage_lock);
		return -ENOENT;
	}
	read_unlock_bh(&web100_linkage_lock);
	web100_stats_unuse(stats);
	
	return 0;
}

/**  /proc/web100/<connection>/<binary variable files>  **/
static ssize_t connection_file_rw(int read, struct file *file,
	char *buf, size_t nbytes, loff_t *ppos)
{
	int low_ino = low_from_ino(file->f_dentry->d_inode->i_ino);
	int cid = cid_from_ino(file->f_dentry->d_inode->i_ino);
	struct web100stats *stats;
	struct web100_file *fp;
	struct web100_var *vp;
	int pos;
	int n;
	int err;
	web100_rwfunc_t rwfunc;
	char *page;
	
	/* We're only going to let them read one page at a time.
	 * We shouldn't ever read more than a page, anyway, though.
	 */
	if (nbytes > PAGE_SIZE)
		nbytes = PAGE_SIZE;
	
	if (!access_ok(read ? VERIFY_WRITE : VERIFY_READ, buf, nbytes))
		return -EFAULT;
	
	if ((page = (char *)__get_free_page(GFP_KERNEL)) == NULL)
		return -ENOMEM;
	
	if (!read) {
		if (copy_from_user(page, buf, nbytes))
			return -EFAULT;
	}
	
	fp = web100_file_lookup(low_ino);
	if (fp == NULL) {
		printk("Unregistered Web100 file.\n");
		return 0;
	}
	
	read_lock_bh(&web100_linkage_lock);
	stats = web100stats_lookup(cid);
	read_unlock_bh(&web100_linkage_lock);
	if (stats == NULL)
		return -ENOENT;
	
	lock_sock(stats->wc_sk);
	
	/* TODO: seek in constant time, not linear.  -JWH */
	pos = 0;
	n = 0;
	vp = fp->first_var;
	while (vp && nbytes > n) {
		if (pos > *ppos) {
			err = -ESPIPE;
			goto err_out;
		}
		if (pos == *ppos) {
			if (vp->len > nbytes - n)
				break;
			
			if (read)
				rwfunc = vp->read;
			else
				rwfunc = vp->write;
			if (rwfunc == NULL) {
				err = -EACCES;
				goto err_out;
			}
			
			err = rwfunc(page + n, stats, vp);
			
			if (err < 0)
				goto err_out;
			n += vp->len;
			*ppos += vp->len;
		}
		pos += vp->len;
		vp = vp->next;
	}
	
	release_sock(stats->wc_sk);
	
	if (read) {
		if (copy_to_user(buf, page, n))
			return -EFAULT;
	}
	free_page((unsigned long)page);
	
	return n;

err_out:
	release_sock(stats->wc_sk);
	
	return err;
}

static ssize_t connection_file_read(struct file *file,
	char *buf, size_t nbytes, loff_t *ppos)
{
	return connection_file_rw(1, file, buf, nbytes, ppos);
}

static ssize_t connection_file_write(struct file *file,
	const char *buf, size_t nbytes, loff_t *ppos)
{
	return connection_file_rw(0, file, (char *)buf, nbytes, ppos);
}

static struct file_operations connection_file_fops = {
	open:		connection_file_open,
	release:	connection_file_release,
	read:		connection_file_read,
	write:		connection_file_write
};


static size_t v6addr_str(char *dest, short *addr)
{
	int start = -1, end = -1;
	int i, j;
	int pos;

	/* Find longest subsequence of 0's in addr */
	for (i = 0; i < 8; i++) {
		if (addr[i] == 0) {
			for (j = i + 1; addr[j] == 0 && j < 8; j++);
			if (j - i > end - start) {
				end = j;
				start = i;
			}
			i = j;
		}
	}
	if (end - start == 1)
		start = -1;

	pos = 0;
	for (i = 0; i < 8; i++) {
		if (i > 0)
			pos += sprintf(dest + pos, ":");
		if (i == start) {
			pos += sprintf(dest + pos, ":");
			i += end - start - 1;
		} else {
			pos += sprintf(dest + pos, "%hx", ntohs(addr[i]));
		}
	}

	return pos;
}

/**  /proc/web100/<connection>/spec_ascii  **/
static ssize_t connection_spec_ascii_read(struct file * file, char * buf,
	size_t nbytes, loff_t *ppos)
{
	__u32 local_addr, remote_addr;
	__u16 local_port, remote_port;
	int cid;
	struct web100stats *stats;
	struct web100directs *vars;
	char tmpbuf[100];
	int len = 0;
	
	if (*ppos != 0)
		return 0;
	
	cid = cid_from_ino(file->f_dentry->d_parent->d_inode->i_ino);
	
	read_lock_bh(&web100_linkage_lock);
	stats = web100stats_lookup(cid);
	read_unlock_bh(&web100_linkage_lock);
	if (stats == NULL)
		return -ENOENT;
	vars = &stats->wc_vars;
	
	if (vars->LocalAddressType == WC_ADDRTYPE_IPV4) {
		/* These values should not change while stats are linked.
		 * We don't need to lock the sock. */
		local_addr = ntohl(vars->LocalAddress.v4addr);
		remote_addr = ntohl(vars->RemAddress.v4addr);
		local_port = vars->LocalPort;
		remote_port = vars->RemPort;
		
		len = sprintf(tmpbuf, "%d.%d.%d.%d:%d %d.%d.%d.%d:%d\n",
			(local_addr >> 24) & 0xff,
			(local_addr >> 16) & 0xff,
			(local_addr >> 8) & 0xff,
			local_addr & 0xff,
			local_port,
			(remote_addr >> 24) & 0xff,
			(remote_addr >> 16) & 0xff,
			(remote_addr >> 8) & 0xff,
			remote_addr & 0xff,
			remote_port);
	} else if (vars->LocalAddressType == WC_ADDRTYPE_IPV6) {
		local_port = vars->LocalPort;
		remote_port = vars->RemPort;
		
		len += v6addr_str(tmpbuf + len, (short *)&vars->LocalAddress.v6addr.addr);
		len += sprintf(tmpbuf + len, ".%d ", local_port);
		len += v6addr_str(tmpbuf + len, (short *)&vars->RemAddress.v6addr.addr);
		len += sprintf(tmpbuf + len, ".%d\n", remote_port);
	} else {
		printk(KERN_ERR "connection_spec_ascii_read: LocalAddressType invalid\n");
		return 0;
	}
	
	len = len > nbytes ? nbytes : len;
	if (copy_to_user(buf, tmpbuf, len))
		return -EFAULT;
	*ppos += len;
	return len;
}

static struct file_operations connection_spec_ascii_fops = {
	open:		connection_file_open,
	release:	connection_file_release,
	read:		connection_spec_ascii_read
};


/**  /proc/web100/<connection>/  **/
static int connection_dir_readdir(struct file *filp,
	void *dirent, filldir_t filldir)
{
	int i;
	struct inode *inode = filp->f_dentry->d_inode;
	struct web100_file *p;
	
	i = filp->f_pos;
	switch (i) {
	case 0:
		if (filldir(dirent, ".", 1, i, inode->i_ino, DT_DIR) < 0)
			return 0;
		i++;
		filp->f_pos++;
		/* fall through */
	case 1:
		if (filldir(dirent, "..", 2, i, proc_web100_dir->low_ino, DT_DIR) < 0)
			return 0;
		i++;
		filp->f_pos++;
		/* fall through */
	default:
		i -= 2;
		if (i >= WEB100_FILE_ARR_SIZE)
			return 1;
		p = &web100_file_arr[i];
		while (p->name) {
			if (filldir(dirent, p->name, p->len, filp->f_pos,
				    ino_from_parts(inode->i_ino, p->low_ino),
				    p->mode >> 12) < 0)
				return 0;
			filp->f_pos++;
			p++;
		}
	}
	
	return 1;
}

static struct dentry *connection_dir_lookup(struct inode *dir,
	struct dentry *dentry, struct nameidata *nd)
{
	struct inode *inode;
	struct web100_file *p;
	struct web100stats *stats;
	uid_t uid;
	
	inode = NULL;
	for (p = &web100_file_arr[0]; p->name; p++) {
		if (p->len != dentry->d_name.len)
			continue;
		if (!memcmp(dentry->d_name.name, p->name, p->len))
			break;
	}
	if (!p->name)
		return ERR_PTR(-ENOENT);
	
	read_lock_bh(&web100_linkage_lock);
	if ((stats = web100stats_lookup(cid_from_ino(dir->i_ino))) == NULL) {
		read_unlock_bh(&web100_linkage_lock);
		printk("connection_dir_lookup: stats == NULL\n");
		return ERR_PTR(-ENOENT);
	}
	uid = sock_i_uid(stats->wc_sk);
	read_unlock_bh(&web100_linkage_lock);
	
	inode = proc_web100_make_inode(dir->i_sb, ino_from_parts(dir->i_ino, p->low_ino));
	if (!inode)
		return ERR_PTR(-ENOMEM);
	inode->i_mode = p->mode ? p->mode : S_IFREG | sysctl_web100_fperms;
	inode->i_uid = uid;
	inode->i_gid = sysctl_web100_gid;
	
	switch (p->low_ino) {
	case PROC_CONN_SPEC_ASCII:
		inode->i_fop = &connection_spec_ascii_fops;
		break;
	case PROC_CONN_SPEC:
	case PROC_CONN_READ:
	case PROC_CONN_TEST:
	case PROC_CONN_TUNE:
		inode->i_fop = &connection_file_fops;
		break;
	default:
		printk("Web100: impossible type (%d)\n", p->low_ino);
		iput(inode);
		return ERR_PTR(-EINVAL);
	}
	
	d_add(dentry, inode);
	return NULL;
}

static struct inode_operations connection_dir_iops = {
	.lookup		= connection_dir_lookup
};

static struct file_operations connection_dir_fops = {
	.readdir	= connection_dir_readdir
};


/**  /proc/web100/header  **/
static ssize_t header_read(struct file * file, char * buf,
	size_t nbytes, loff_t *ppos)
{
	int len = 0;
	loff_t offset;
	char *tmpbuf;
	struct web100_file *fp;
	struct web100_var *vp;
	int n, tmp;
	int i;
	int ret = 0;
	
	/* We will assume the variable description list will not change
	 * after init.  (True at least right now.) Otherwise, we would have
	 * to have a lock on it.
	 */
	
	if ((tmpbuf = (char *)__get_free_page(GFP_KERNEL)) == NULL)
		return -ENOMEM;
	
	offset = sprintf(tmpbuf, "%s\n", web100_version_string);
	
	for (i = 0; i < WEB100_FILE_ARR_SIZE; i++) {
		int file_offset = 0;
		
		if ((fp = &web100_file_arr[i]) == NULL)
			continue;
		
		if (fp->first_var == NULL)
			continue;
		
		offset += sprintf(tmpbuf + offset, "\n/%s\n", fp->name);
		
		vp = fp->first_var;
		while (vp) {
			if (offset > WEB100MIB_BLOCK_SIZE) {
				len += offset;
				if (*ppos < len) {
					n = min(offset, min_t(loff_t, nbytes, len - *ppos));
					if (copy_to_user(buf, tmpbuf + max_t(loff_t, *ppos - len + offset, 0), n))
						return -EFAULT;
					buf += n;
					if (nbytes == n) {
						*ppos += n;
						ret = n;
						goto out;
					}
				}
				offset = 0;
			}
			
			offset += sprintf(tmpbuf + offset, "%s %d %d %d\n",
					  vp->name, file_offset, vp->type, vp->len);
			file_offset += vp->len;
			
			vp = vp->next;
		}
	}
	len += offset;
	if (*ppos < len) {
		n = min(offset, min_t(loff_t, nbytes, len - *ppos));
		if (copy_to_user(buf, tmpbuf + max_t(loff_t, *ppos - len + offset, 0), n))
			return -EFAULT;
		if (nbytes <= len - *ppos) {
			*ppos += nbytes;
			ret = nbytes;
			goto out;
		} else {
			tmp = len - *ppos;
			*ppos = len;
			ret = tmp;
			goto out;
		}
	}
	
out:
	free_page((unsigned long)tmpbuf);
	return ret;
}

static struct file_operations header_file_operations = {
	read:		header_read
};


/**  /proc/web100/  **/
#define FIRST_CONNECTION_ENTRY	256
#define NUMBUF_LEN		11

static int get_connection_list(int pos, int *cids, int max)
{
	struct web100stats *stats;
	int n;
	
	pos -= FIRST_CONNECTION_ENTRY;
	n = 0;
	
	read_lock_bh(&web100_linkage_lock);
	
	stats = web100stats_first;
	while (stats && n < max) {
		if (!stats->wc_dead) {
			if (pos <= 0)
				cids[n++] = stats->wc_cid;
			else
				pos--;
		}
		
		stats = stats->wc_next;
	}
	
	read_unlock_bh(&web100_linkage_lock);
	
	return n;
}

static int cid_to_str(int cid, char *buf)
{
	int len, tmp, i;
	
	if (cid == 0) { /* a special case */
		len = 1;
	} else {
		tmp = cid;
		for (len = 0; len < NUMBUF_LEN - 1 && tmp > 0; len++)
			tmp /= 10;
	}
	
	for (i = 0; i < len; i++) {
		buf[len - i - 1] = '0' + (cid % 10);
		cid /= 10;
	}
	buf[len] = '\0';
	
	return len;
}

static int web100_dir_readdir(struct file *filp,
	void *dirent, filldir_t filldir)
{
	int err;
	unsigned n, i;
	int *cids;
	int len;
	ino_t ino;
	char name[NUMBUF_LEN];
	int n_conns;
	
	if (filp->f_pos < FIRST_CONNECTION_ENTRY) {
		if ((err = proc_readdir(filp, dirent, filldir)) < 0)
			return err;
		filp->f_pos = FIRST_CONNECTION_ENTRY;
	}
	n_conns = WEB100_MAX_CONNS * 2;
	do {
		n_conns /= 2;
		cids = kmalloc(n_conns * sizeof (int), GFP_KERNEL);
	} while (cids == NULL && n_conns > 0);
	if (cids == NULL)
		return -ENOMEM;
	n = get_connection_list(filp->f_pos, cids, n_conns);
	
	for (i = 0; i < n; i++) {
		ino = ino_from_cid(cids[i]);
		len = cid_to_str(cids[i], name);
		if (filldir(dirent, name, len, filp->f_pos,
			    ino, DT_DIR) < 0) {
			break;
		}
		filp->f_pos++;
	}
	
	kfree(cids);
	
	return 0;
}

static inline struct dentry *web100_dir_dent(void)
{
	struct qstr qstr;
	
	qstr.name = "web100";
	qstr.len = 6;
	qstr.hash = full_name_hash(qstr.name, qstr.len);
	
	return d_lookup(proc_mnt->mnt_sb->s_root, &qstr);
}

void web100_proc_nlink_update(nlink_t nlink)
{
	struct dentry *dent;
	
	dent = web100_dir_dent();
	if (dent)
		dent->d_inode->i_nlink = nlink;
	dput(dent);
}

int web100_proc_dointvec_update(ctl_table *ctl, int write, struct file *filp,
                               void *buffer, size_t *lenp, loff_t *ppos)
{
	unsigned n, i;
	int *cids;
	int err;
	struct qstr qstr;
	struct dentry *web100_dent, *conn_dent, *dent;
	struct inode *inode;
	struct web100_file *p;
	char name[NUMBUF_LEN];
	
	if ((err = proc_dointvec(ctl, write, filp, buffer, lenp, ppos)) != 0)
		return err;
	
	if ((web100_dent = web100_dir_dent()) == NULL)
		return 0;
	
	if ((cids = kmalloc(WEB100_MAX_CONNS * sizeof (int), GFP_KERNEL)) == NULL)
		return -ENOMEM;
	n = get_connection_list(FIRST_CONNECTION_ENTRY, cids, WEB100_MAX_CONNS);
	for (i = 0; i < n; i++) {
		qstr.len = cid_to_str(cids[i], name);
		qstr.name = name;
		qstr.hash = full_name_hash(qstr.name, qstr.len);
		if ((conn_dent = d_lookup(web100_dent, &qstr)) != NULL) {
			for (p = &web100_file_arr[0]; p->name; p++) {
				qstr.name = p->name;
				qstr.len = p->len;
				qstr.hash = full_name_hash(qstr.name, qstr.len);
				if ((dent = d_lookup(conn_dent, &qstr)) != NULL) {
					inode = dent->d_inode;
					if ((inode->i_mode = p->mode) == 0)
						inode->i_mode = S_IFREG | sysctl_web100_fperms;
					inode->i_gid = sysctl_web100_gid;
					dput(dent);
				}
			}
			dput(conn_dent);
		}
	}
	dput(web100_dent);
	kfree(cids);
	
	return 0;
}

static int web100_proc_connection_revalidate(struct dentry *dentry, struct nameidata *nd)
{
	int ret = 1;
	
	if (dentry->d_inode == NULL)
		return 0;
	read_lock_bh(&web100_linkage_lock);
	if (web100stats_lookup(cid_from_ino(dentry->d_inode->i_ino)) == NULL) {
		ret = 0;
		d_drop(dentry);
	}
	read_unlock_bh(&web100_linkage_lock);
	
	return ret;
}

static struct dentry_operations web100_dir_dentry_operations = {
	d_revalidate:	web100_proc_connection_revalidate
};

static struct dentry *web100_dir_lookup(struct inode *dir,
	struct dentry *dentry, struct nameidata *nd)
{
	char *name;
	int len;
	int cid;
	unsigned c;
	struct inode *inode;
	unsigned long ino;
	struct web100stats *stats;
	
	if (proc_lookup(dir, dentry, nd) == NULL)
		return NULL;
	
	cid = 0;
	name = (char *)(dentry->d_name.name);
	len = dentry->d_name.len;
	if (len <= 0)	/* I don't think this can happen */
		return ERR_PTR(-EINVAL);
	while (len-- > 0) {
		c = *name - '0';
		name++;
		cid *= 10;
		cid += c;
		if (c > 9 || c < 0 || (cid == 0 && len != 0) || cid >= WEB100_MAX_CONNS) {
			cid = -1;
			break;
		}
	}
	if (cid < 0)
		return ERR_PTR(-ENOENT);
	
	read_lock_bh(&web100_linkage_lock);
	stats = web100stats_lookup(cid);
	if (stats == NULL || stats->wc_dead) {
		read_unlock_bh(&web100_linkage_lock);
		return ERR_PTR(-ENOENT);
	}
	read_unlock_bh(&web100_linkage_lock);
	
	ino = ino_from_cid(cid);
	inode = proc_web100_make_inode(dir->i_sb, ino);
	if (inode == NULL)
		return ERR_PTR(-ENOMEM);
	inode->i_nlink = 2;
	inode->i_mode = S_IFDIR | S_IRUGO | S_IXUGO;
	inode->i_flags |= S_IMMUTABLE; /* ? */
	inode->i_op = &connection_dir_iops;
	inode->i_fop = &connection_dir_fops;
	
	dentry->d_op = &web100_dir_dentry_operations;
	d_add(dentry, inode);
	return NULL;
}

static struct file_operations web100_dir_fops = {
	.readdir	= web100_dir_readdir
};

static struct inode_operations web100_dir_iops = {
	.lookup		= web100_dir_lookup
};


/*
 * Read/write handlers
 */

/* A read handler for reading directly from the stats */
/* read_data is the byte offset into struct web100stats */
static int read_stats(void *buf, struct web100stats *stats,
			   struct web100_var *vp)
{
	memcpy(buf, (char *)stats + vp->read_data, vp->len);
	
	return 0;
}

/* A write handler for writing directly to the stats */
/* write_data is a byte offset into struct web100stats */
static int write_stats(void *buf, struct web100stats *stats,
			    struct web100_var *vp)
{
	memcpy((char *)stats + vp->read_data, buf, vp->len);
	
	return 0;
}

int read_LimCwnd(void *buf, struct web100stats *stats, struct web100_var *vp)
{
	struct tcp_sock *tp = tcp_sk(stats->wc_sk);
	__u32 tmp = (__u32)(tp->snd_cwnd_clamp * tp->mss_cache);

	memcpy(buf, &tmp, 4);

	return 0;
}

int write_LimCwnd(void *buf, struct web100stats *stats, struct web100_var *vp)
{
	struct tcp_sock *tp = tcp_sk(stats->wc_sk);
	
	tp->snd_cwnd_clamp = min(*(__u32 *)buf / tp->mss_cache, 65535U);
	
	return 0;
}

int write_LimRwin(void *buf, struct web100stats *stats, struct web100_var *vp)
{
	__u32 val = *(__u32 *)buf;
	struct tcp_sock *tp = tcp_sk(stats->wc_sk);
	
	stats->wc_vars.LimRwin = tp->window_clamp =
		min(val, 65535U << tp->rx_opt.rcv_wscale);
	
	return 0;
}

int write_Sndbuf(void *buf, struct web100stats *stats, struct web100_var *vp)
{
	int val;
	struct sock *sk = stats->wc_sk;
	
	memcpy(&val, buf, sizeof (int));
	
	sk->sk_userlocks |= SOCK_SNDBUF_LOCK;
	sk->sk_sndbuf = max_t(int, SOCK_MIN_SNDBUF, min_t(int, sysctl_wmem_max, val));
	sk->sk_write_space(sk);

	return 0;
}

int write_Rcvbuf(void *buf, struct web100stats *stats, struct web100_var *vp)
{
	int val;
	struct sock *sk = stats->wc_sk;
	
	memcpy(&val, buf, sizeof (int));
	
	sk->sk_userlocks |= SOCK_RCVBUF_LOCK;
	sk->sk_rcvbuf = max_t(int, SOCK_MIN_RCVBUF, min_t(int, sysctl_rmem_max, val));
	
	return 0;
}

int write_State(void *buf, struct web100stats *stats, struct web100_var *vp)
{
	int val;
	struct sock *sk = stats->wc_sk;
	
	memcpy(&val, buf, sizeof (int));
	if (val != 12) /* deleteTCB, RFC 2012 */
		return -EINVAL;
	sk->sk_prot->disconnect(sk, 0);
	
	return 0;
}

extern __u32 sysctl_wmem_default;
extern __u32 sysctl_rmem_default;

/* A read handler for reading directly from the sk */
/* read_data is a byte offset into the sk */
static int read_sk(void *buf, struct web100stats *stats,
			  struct web100_var *vp)
{
	/* Fill data with 0's if the connection is gone. */
	if (stats->wc_sk == NULL)
		memset(buf, 0, vp->len);
	else
		memcpy(buf, (char *)(stats->wc_sk) + vp->read_data, vp->len);
	
	return 0;
}

static int write_sk(void *buf, struct web100stats *stats, struct web100_var *vp)
{
	if (stats->wc_sk == NULL)
		return -EIO;
	else
		memcpy((char *)(stats->wc_sk) + vp->write_data, buf, vp->len);
	
	return 0;
}

__u64 web100_mono_time()
{
#if 1
	struct timespec now;
	
	do_posix_clock_monotonic_gettime(&now);
	
	return 1000000ULL * (__u64)now.tv_sec + now.tv_nsec / 1000;
#else
	struct timeval now;
	static struct timeval before;

	do_gettimeofday(&now);

	/* assure monotonic, no matter what */
	if ((now.tv_sec > before.tv_sec) ||
	    ((now.tv_sec == before.tv_sec) && (now.tv_usec > before.tv_usec))) {
		before = now;
	} else {
		before.tv_usec++;
		if (before.tv_usec >= 1000000) {
			before.tv_usec -= 1000000;
			before.tv_sec++;
		}
	}
	
	return (1000000ULL * (__u64)before.tv_sec + before.tv_usec);
#endif
}

/* A read handler to get the low part of the current time in usec */
static int read_now(void *buf, struct web100stats *stats,
			  struct web100_var *vp)
{
	__u64 val;

	val = web100_mono_time();
	val -= stats->wc_start_monotime;
	memcpy(buf, (char *)&val, vp->len);

	return 0;
}

#ifdef CONFIG_WEB100_NET100
static int write_mss(void *buf, struct web100stats *stats, struct web100_var *vp)
{
	struct sock *sk = stats->wc_sk;
	struct tcp_sock *tp;
	__u32 val = *(__u32 *)buf;
	
	if (sk == NULL)
		return -EIO;
	tp = tcp_sk(sk);
	
	if (val > tp->mss_cache)
		return -EINVAL;
	if (val < 1)
		return -EINVAL;
	
	tp->mss_cache = val;
	web100_update_mss(tp);
	
	return 0;
}

static int write_CwndAdjust(void *buf, struct web100stats *stats, struct web100_var *vp)
{
	struct sock *sk = stats->wc_sk;
	struct tcp_sock *tp;
	
	if (sk == NULL)
		return -EIO;
	tp = tcp_sk(sk);
	
	memcpy(&stats->wc_vars.WAD_CwndAdjust, buf, 4);
	tp->snd_ssthresh = min_t(__u32, tp->snd_ssthresh,
	                         tp->snd_cwnd + stats->wc_vars.WAD_CwndAdjust);
	
	return 0;
}
#endif

#if 0
static int rw_noop(void *buf, struct web100stats *stats, struct web100_var *vp)
{
	return 0;
}
#endif

/*
 * init
 */

void __init proc_web100_init(void)
{
	/* Set up the proc files. */
	proc_web100_dir = proc_mkdir("web100", NULL);
	proc_web100_dir->proc_iops = &web100_dir_iops;
	proc_web100_dir->proc_fops = &web100_dir_fops;
	
	proc_web100_header = create_proc_entry("header", S_IFREG | S_IRUGO,
					       proc_web100_dir);
	proc_web100_header->proc_fops = &header_file_operations;
	
	/* Set up the contents of the proc files. */
#define OFFSET_IN(type,var)	((unsigned long)(&(((type *)NULL)->var)))
#define OFFSET_ST(field) ((unsigned long)(&(((struct web100stats *)NULL)->wc_vars.field)))
#define OFFSET_SK(field) ((unsigned long)(&(((struct sock *)NULL)->field)))
#define OFFSET_TP(field) ((unsigned long)(&(tcp_sk(NULL)->field)))

#define ADD_RO_STATSVAR(ino,name,type)	\
add_var(web100_file_lookup(ino), #name, type, \
	read_stats, OFFSET_ST(name), NULL, 0)

#define ADD_RO_STATSRENAME(ino,name,type,var)	\
add_var(web100_file_lookup(ino), name, type, \
	read_stats, OFFSET_ST(var), NULL, 0)

#define ADD_RO_STATSVAR_DEP(ino,name,type)	\
add_var(web100_file_lookup(ino), "_" #name, type, \
	read_stats, OFFSET_ST(name), NULL, 0)

#define ADD_WO_STATSVAR(ino,name,type)	\
add_var(web100_file_lookup(ino), #name, type, NULL, 0, \
	write_stats, OFFSET_ST(name))

#define ADD_WO_STATSVAR_DEP(ino,name,type)	\
add_var(web100_file_lookup(ino), "_" #name, type, NULL, 0, \
	write_stats, OFFSET_ST(name))

#define ADD_RW_STATSVAR(ino,name,type)	\
add_var(web100_file_lookup(ino), #name, type, \
	read_stats, OFFSET_ST(name), \
	write_stats, OFFSET_ST(name))

#define ADD_RW_STATSVAR_DEP(ino,name,type)	\
add_var(web100_file_lookup(ino), "_" #name, type, \
	read_stats, OFFSET_ST(name), \
	write_stats, OFFSET_ST(name))

#define ADD_RO_SKVAR(ino,name,type,var) \
add_var(web100_file_lookup(ino), #name, type, \
	read_sk, OFFSET_SK(var), NULL, 0)

#define ADD_RW_SKVAR(ino,name,type,var) \
add_var(web100_file_lookup(ino), #name, type, \
	read_sk, OFFSET_SK(var), write_sk, OFFSET_SK(var))

#define ADD_RO_TPVAR(ino,name,type,var) \
add_var(web100_file_lookup(ino), #name, type, \
	read_sk, OFFSET_TP(var), write_sk, OFFSET_TP(var))

#define ADD_NOOP(ino,name,type) \
add_var(web100_file_lookup(ino), #name, type, \
	rw_noop, 0, rw_noop, 0)

	/* spec */
	ADD_RO_STATSVAR(PROC_CONN_SPEC, LocalAddressType, WEB100_TYPE_INTEGER);
	ADD_RO_STATSVAR(PROC_CONN_SPEC, LocalAddress, WEB100_TYPE_INET_ADDRESS);
	ADD_RO_STATSVAR(PROC_CONN_SPEC, LocalPort, WEB100_TYPE_INET_PORT_NUMBER);
	ADD_RO_STATSVAR(PROC_CONN_SPEC, RemAddress, WEB100_TYPE_INET_ADDRESS);
	ADD_RO_STATSVAR(PROC_CONN_SPEC, RemPort, WEB100_TYPE_INET_PORT_NUMBER);
	ADD_RO_STATSRENAME(PROC_CONN_SPEC, "_RemoteAddress", WEB100_TYPE_INET_ADDRESS, RemAddress);
	ADD_RO_STATSRENAME(PROC_CONN_SPEC, "_RemotePort", WEB100_TYPE_INET_PORT_NUMBER, RemPort);
	
	/* read */
	/* STATE */
	ADD_RO_STATSVAR(PROC_CONN_READ, State, WEB100_TYPE_INTEGER);
	ADD_RO_STATSVAR(PROC_CONN_READ, SACKEnabled, WEB100_TYPE_INTEGER);
	ADD_RO_STATSVAR(PROC_CONN_READ, TimestampsEnabled, WEB100_TYPE_INTEGER);
	ADD_RO_STATSVAR(PROC_CONN_READ, NagleEnabled, WEB100_TYPE_INTEGER);
	ADD_RO_STATSVAR(PROC_CONN_READ, ECNEnabled, WEB100_TYPE_INTEGER);
	ADD_RO_STATSVAR(PROC_CONN_READ, SndWinScale, WEB100_TYPE_INTEGER);
	ADD_RO_STATSVAR(PROC_CONN_READ, RcvWinScale, WEB100_TYPE_INTEGER);
	
	/* SYN OPTIONS */
	ADD_RO_STATSVAR(PROC_CONN_READ, ActiveOpen, WEB100_TYPE_INTEGER);
	ADD_RO_STATSVAR(PROC_CONN_READ, MSSRcvd, WEB100_TYPE_GAUGE32);
	ADD_RO_STATSVAR(PROC_CONN_READ, WinScaleRcvd, WEB100_TYPE_INTEGER);
	ADD_RO_STATSVAR(PROC_CONN_READ, WinScaleSent, WEB100_TYPE_INTEGER);
	
	/* DATA */
	ADD_RO_STATSVAR(PROC_CONN_READ, PktsOut, WEB100_TYPE_COUNTER32);
	ADD_RO_STATSVAR(PROC_CONN_READ, DataPktsOut, WEB100_TYPE_COUNTER32);
	ADD_RO_STATSVAR_DEP(PROC_CONN_READ, AckPktsOut, WEB100_TYPE_COUNTER32);
	ADD_RO_STATSVAR(PROC_CONN_READ, DataBytesOut, WEB100_TYPE_COUNTER64);
	ADD_RO_STATSVAR(PROC_CONN_READ, PktsIn, WEB100_TYPE_COUNTER32);
	ADD_RO_STATSVAR(PROC_CONN_READ, DataPktsIn, WEB100_TYPE_COUNTER32);
	ADD_RO_STATSVAR_DEP(PROC_CONN_READ, AckPktsIn, WEB100_TYPE_COUNTER32);
	ADD_RO_STATSVAR(PROC_CONN_READ, DataBytesIn, WEB100_TYPE_COUNTER64);
	ADD_RO_STATSVAR(PROC_CONN_READ, SndUna, WEB100_TYPE_COUNTER32);
	ADD_RO_STATSVAR(PROC_CONN_READ, SndNxt, WEB100_TYPE_UNSIGNED32);
	ADD_RO_STATSVAR(PROC_CONN_READ, SndMax, WEB100_TYPE_COUNTER32);
	ADD_RO_STATSRENAME(PROC_CONN_READ, "_snd_una", WEB100_TYPE_COUNTER32, SndUna);
	ADD_RO_STATSRENAME(PROC_CONN_READ, "_snd_nxt", WEB100_TYPE_COUNTER32, SndNxt);
	ADD_RO_STATSRENAME(PROC_CONN_READ, "_snd_max", WEB100_TYPE_COUNTER32, SndMax);
	ADD_RO_STATSVAR(PROC_CONN_READ, ThruBytesAcked, WEB100_TYPE_COUNTER64);
	ADD_RO_STATSRENAME(PROC_CONN_READ, "_ThruBytesSent", WEB100_TYPE_COUNTER64, ThruBytesAcked);
	ADD_RO_STATSVAR(PROC_CONN_READ, SndISS, WEB100_TYPE_COUNTER32);
	ADD_RO_STATSVAR_DEP(PROC_CONN_READ, SendWraps, WEB100_TYPE_COUNTER32);
	ADD_RO_STATSVAR(PROC_CONN_READ, RcvNxt, WEB100_TYPE_COUNTER32);
	ADD_RO_STATSRENAME(PROC_CONN_READ, "_rcv_nxt", WEB100_TYPE_COUNTER32, RcvNxt);
	ADD_RO_STATSVAR(PROC_CONN_READ, ThruBytesReceived, WEB100_TYPE_COUNTER64);
	ADD_RO_STATSVAR(PROC_CONN_READ, RecvISS, WEB100_TYPE_COUNTER32);
	ADD_RO_STATSVAR_DEP(PROC_CONN_READ, RecvWraps, WEB100_TYPE_COUNTER32);
	ADD_RO_STATSVAR_DEP(PROC_CONN_READ, StartTime, WEB100_TYPE_INTEGER32);
	ADD_RO_STATSVAR(PROC_CONN_READ, StartTimeSec, WEB100_TYPE_INTEGER32);
	ADD_RO_STATSVAR(PROC_CONN_READ, StartTimeUsec, WEB100_TYPE_INTEGER32);
	add_var(web100_file_lookup(PROC_CONN_READ), "Duration", WEB100_TYPE_COUNTER64, read_now, 0, NULL, 0);
	add_var(web100_file_lookup(PROC_CONN_READ), "_CurrTime", WEB100_TYPE_COUNTER64, read_now, 0, NULL, 0);

	/* SENDER CONGESTION */
	ADD_RO_STATSRENAME(PROC_CONN_READ, "SndLimTransSender", WEB100_TYPE_COUNTER32, SndLimTrans[WC_SNDLIM_SENDER]);
	ADD_RO_STATSRENAME(PROC_CONN_READ, "SndLimBytesSender", WEB100_TYPE_COUNTER64, SndLimBytes[WC_SNDLIM_SENDER]);
	ADD_RO_STATSRENAME(PROC_CONN_READ, "SndLimTimeSender", WEB100_TYPE_COUNTER32, SndLimTime[WC_SNDLIM_SENDER]);
	ADD_RO_STATSRENAME(PROC_CONN_READ, "SndLimTransCwnd", WEB100_TYPE_COUNTER32, SndLimTrans[WC_SNDLIM_CWND]);
	ADD_RO_STATSRENAME(PROC_CONN_READ, "SndLimBytesCwnd", WEB100_TYPE_COUNTER64, SndLimBytes[WC_SNDLIM_CWND]);
	ADD_RO_STATSRENAME(PROC_CONN_READ, "SndLimTimeCwnd", WEB100_TYPE_COUNTER32, SndLimTime[WC_SNDLIM_CWND]);
	ADD_RO_STATSRENAME(PROC_CONN_READ, "SndLimTransRwin", WEB100_TYPE_COUNTER32, SndLimTrans[WC_SNDLIM_RWIN]);
	ADD_RO_STATSRENAME(PROC_CONN_READ, "SndLimBytesRwin", WEB100_TYPE_COUNTER64, SndLimBytes[WC_SNDLIM_RWIN]);
	ADD_RO_STATSRENAME(PROC_CONN_READ, "SndLimTimeRwin", WEB100_TYPE_COUNTER32, SndLimTime[WC_SNDLIM_RWIN]);
	ADD_RO_STATSVAR(PROC_CONN_READ, SlowStart, WEB100_TYPE_COUNTER32);
	ADD_RO_STATSVAR(PROC_CONN_READ, CongAvoid, WEB100_TYPE_COUNTER32);
	ADD_RO_STATSVAR(PROC_CONN_READ, CongestionSignals, WEB100_TYPE_COUNTER32);
	ADD_RO_STATSVAR(PROC_CONN_READ, OtherReductions, WEB100_TYPE_COUNTER32);
	ADD_RO_STATSVAR(PROC_CONN_READ, X_OtherReductionsCV, WEB100_TYPE_COUNTER32);
	ADD_RO_STATSVAR(PROC_CONN_READ, X_OtherReductionsCM, WEB100_TYPE_COUNTER32);
	ADD_RO_STATSVAR(PROC_CONN_READ, CongestionOverCount, WEB100_TYPE_COUNTER32);
	ADD_RO_STATSRENAME(PROC_CONN_READ, "_Recoveries", WEB100_TYPE_COUNTER32, CongestionSignals);
	ADD_RO_STATSVAR(PROC_CONN_READ, CurCwnd, WEB100_TYPE_GAUGE32);
	ADD_RO_STATSRENAME(PROC_CONN_READ, "_CurrentCwnd", WEB100_TYPE_GAUGE32, CurCwnd);
	ADD_RO_STATSVAR(PROC_CONN_READ, MaxCwnd, WEB100_TYPE_GAUGE32);
	ADD_RO_STATSVAR(PROC_CONN_READ, CurSsthresh, WEB100_TYPE_GAUGE32);
	ADD_RO_STATSRENAME(PROC_CONN_READ, "_CurrentSsthresh", WEB100_TYPE_GAUGE32, CurSsthresh);
	add_var(web100_file_lookup(PROC_CONN_READ), "LimCwnd", WEB100_TYPE_GAUGE32, read_LimCwnd, 0, NULL, 0);
	ADD_RO_STATSVAR(PROC_CONN_READ, MaxSsthresh, WEB100_TYPE_GAUGE32);
	ADD_RO_STATSVAR(PROC_CONN_READ, MinSsthresh, WEB100_TYPE_GAUGE32);

	/* SENDER PATH MODEL */
	ADD_RO_STATSVAR(PROC_CONN_READ, FastRetran, WEB100_TYPE_COUNTER32);
	ADD_RO_STATSVAR(PROC_CONN_READ, Timeouts, WEB100_TYPE_COUNTER32);
	ADD_RO_STATSVAR(PROC_CONN_READ, SubsequentTimeouts, WEB100_TYPE_COUNTER32);
	ADD_RO_STATSVAR(PROC_CONN_READ, CurTimeoutCount, WEB100_TYPE_GAUGE32);
	ADD_RO_STATSRENAME(PROC_CONN_READ, "_CurrTimeoutCount", WEB100_TYPE_GAUGE32, CurTimeoutCount);
	ADD_RO_STATSVAR(PROC_CONN_READ, AbruptTimeouts, WEB100_TYPE_COUNTER32);
	ADD_RO_STATSVAR(PROC_CONN_READ, PktsRetrans, WEB100_TYPE_COUNTER32);
	ADD_RO_STATSVAR(PROC_CONN_READ, BytesRetrans, WEB100_TYPE_COUNTER32);
	ADD_RO_STATSVAR(PROC_CONN_READ, DupAcksIn, WEB100_TYPE_COUNTER32);
	ADD_RO_STATSVAR(PROC_CONN_READ, SACKsRcvd, WEB100_TYPE_COUNTER32);
	ADD_RO_STATSVAR(PROC_CONN_READ, SACKBlocksRcvd, WEB100_TYPE_COUNTER32);
	ADD_RO_STATSVAR(PROC_CONN_READ, PreCongSumCwnd, WEB100_TYPE_COUNTER32);
	ADD_RO_STATSRENAME(PROC_CONN_READ, "_SumCwndAtCong", WEB100_TYPE_COUNTER32, PreCongSumCwnd);
	ADD_RO_STATSVAR(PROC_CONN_READ, PreCongSumRTT, WEB100_TYPE_COUNTER32);
	ADD_RO_STATSVAR_DEP(PROC_CONN_READ, PreCongCountRTT, WEB100_TYPE_COUNTER32);
	ADD_RO_STATSVAR(PROC_CONN_READ, PostCongSumRTT, WEB100_TYPE_COUNTER32);
	ADD_RO_STATSVAR(PROC_CONN_READ, PostCongCountRTT, WEB100_TYPE_COUNTER32);
	ADD_RO_STATSVAR(PROC_CONN_READ, ECERcvd, WEB100_TYPE_COUNTER32);
	ADD_RO_STATSVAR(PROC_CONN_READ, SendStall, WEB100_TYPE_COUNTER32);
	ADD_RO_STATSVAR(PROC_CONN_READ, QuenchRcvd, WEB100_TYPE_COUNTER32);
	ADD_RO_STATSVAR(PROC_CONN_READ, RetranThresh, WEB100_TYPE_GAUGE32);
	ADD_RO_STATSVAR(PROC_CONN_READ, NonRecovDA, WEB100_TYPE_COUNTER32);
	ADD_RO_STATSVAR(PROC_CONN_READ, AckAfterFR, WEB100_TYPE_COUNTER32);
	ADD_RO_STATSVAR(PROC_CONN_READ, DSACKDups, WEB100_TYPE_COUNTER32);
	ADD_RO_STATSVAR(PROC_CONN_READ, SampleRTT, WEB100_TYPE_GAUGE32);
	ADD_RO_STATSRENAME(PROC_CONN_READ, "_SampledRTT", WEB100_TYPE_GAUGE32, SampleRTT);
	ADD_RO_STATSVAR(PROC_CONN_READ, SmoothedRTT, WEB100_TYPE_GAUGE32);
	ADD_RO_STATSVAR(PROC_CONN_READ, RTTVar, WEB100_TYPE_GAUGE32);
	ADD_RO_STATSVAR(PROC_CONN_READ, MaxRTT, WEB100_TYPE_GAUGE32);
	ADD_RO_STATSVAR(PROC_CONN_READ, MinRTT, WEB100_TYPE_GAUGE32);
	ADD_RO_STATSVAR(PROC_CONN_READ, SumRTT, WEB100_TYPE_COUNTER64);
	ADD_RO_STATSVAR(PROC_CONN_READ, CountRTT, WEB100_TYPE_COUNTER32);
	ADD_RO_STATSVAR(PROC_CONN_READ, CurRTO, WEB100_TYPE_GAUGE32);
	ADD_RO_STATSRENAME(PROC_CONN_READ, "_CurrentRTO", WEB100_TYPE_GAUGE32, CurRTO);
	ADD_RO_STATSVAR(PROC_CONN_READ, MaxRTO, WEB100_TYPE_GAUGE32);
	ADD_RO_STATSVAR(PROC_CONN_READ, MinRTO, WEB100_TYPE_GAUGE32);
	ADD_RO_STATSVAR(PROC_CONN_READ, CurMSS, WEB100_TYPE_GAUGE32);
	ADD_RO_STATSRENAME(PROC_CONN_READ, "_CurrentMSS", WEB100_TYPE_GAUGE32, CurMSS);
	ADD_RO_STATSVAR(PROC_CONN_READ, MaxMSS, WEB100_TYPE_GAUGE32);
	ADD_RO_STATSVAR(PROC_CONN_READ, MinMSS, WEB100_TYPE_GAUGE32);

	/* SENDER BUFFER */
#define PROC_CONN_XTEST PROC_CONN_READ	/* lazy */
	ADD_RO_SKVAR(PROC_CONN_READ, _Sndbuf, WEB100_TYPE_GAUGE32, sk_sndbuf);
	ADD_RO_SKVAR(PROC_CONN_READ, X_Sndbuf, WEB100_TYPE_GAUGE32, sk_sndbuf);
	ADD_RO_SKVAR(PROC_CONN_READ, X_Rcvbuf, WEB100_TYPE_GAUGE32, sk_rcvbuf);
	ADD_RO_STATSVAR(PROC_CONN_READ, CurRetxQueue, WEB100_TYPE_GAUGE32);
	ADD_RO_STATSRENAME(PROC_CONN_READ, "_CurRetranQueue", WEB100_TYPE_GAUGE32, CurRetxQueue);
	ADD_RO_STATSVAR(PROC_CONN_READ, MaxRetxQueue, WEB100_TYPE_GAUGE32);
	ADD_RO_STATSRENAME(PROC_CONN_READ, "_MaxRetranQueue", WEB100_TYPE_GAUGE32, MaxRetxQueue);
	ADD_RO_STATSVAR(PROC_CONN_READ, CurAppWQueue, WEB100_TYPE_GAUGE32);
	ADD_RO_STATSVAR(PROC_CONN_READ, MaxAppWQueue, WEB100_TYPE_GAUGE32);
	
	/* SENDER BUFFER TUNING - See below */

	/* LOCAL RECEIVER */
	ADD_RO_STATSVAR(PROC_CONN_READ, CurRwinSent, WEB100_TYPE_GAUGE32);
	ADD_RO_STATSRENAME(PROC_CONN_READ, "_CurrentRwinSent", WEB100_TYPE_GAUGE32, CurRwinSent);
	ADD_RO_STATSVAR(PROC_CONN_READ, MaxRwinSent, WEB100_TYPE_GAUGE32);
	ADD_RO_STATSVAR(PROC_CONN_READ, MinRwinSent, WEB100_TYPE_GAUGE32);
	ADD_RO_STATSVAR(PROC_CONN_READ, LimRwin, WEB100_TYPE_GAUGE32);
	ADD_RO_STATSVAR(PROC_CONN_READ, DupAcksOut, WEB100_TYPE_COUNTER32);
	ADD_RO_SKVAR(PROC_CONN_READ, _Rcvbuf, WEB100_TYPE_GAUGE32, sk_rcvbuf);
	ADD_RO_STATSVAR(PROC_CONN_READ, CurReasmQueue, WEB100_TYPE_GAUGE32);
	ADD_RO_STATSVAR(PROC_CONN_READ, MaxReasmQueue, WEB100_TYPE_GAUGE32);
	ADD_RO_STATSVAR(PROC_CONN_READ, CurAppRQueue, WEB100_TYPE_GAUGE32);
	ADD_RO_STATSVAR(PROC_CONN_READ, MaxAppRQueue, WEB100_TYPE_GAUGE32);
	ADD_RO_TPVAR(PROC_CONN_XTEST, X_rcv_ssthresh, WEB100_TYPE_GAUGE32, rcv_ssthresh);
	ADD_RO_TPVAR(PROC_CONN_XTEST, X_wnd_clamp, WEB100_TYPE_GAUGE32, window_clamp);
	ADD_RO_STATSVAR(PROC_CONN_XTEST, X_dbg1, WEB100_TYPE_GAUGE32);
	ADD_RO_STATSVAR(PROC_CONN_XTEST, X_dbg2, WEB100_TYPE_GAUGE32);
	ADD_RO_STATSVAR(PROC_CONN_XTEST, X_dbg3, WEB100_TYPE_GAUGE32);
	ADD_RO_STATSVAR(PROC_CONN_XTEST, X_dbg4, WEB100_TYPE_GAUGE32);

	/* OBSERVED RECEIVER */
	ADD_RO_STATSVAR(PROC_CONN_READ, CurRwinRcvd, WEB100_TYPE_GAUGE32);
	ADD_RO_STATSRENAME(PROC_CONN_READ, "_CurrentRwinRcvd", WEB100_TYPE_GAUGE32, CurRwinRcvd);
	ADD_RO_STATSVAR(PROC_CONN_READ, MaxRwinRcvd, WEB100_TYPE_GAUGE32);
	ADD_RO_STATSVAR(PROC_CONN_READ, MinRwinRcvd, WEB100_TYPE_GAUGE32);

	/* CONNECTION ID */
	ADD_RO_STATSVAR(PROC_CONN_READ, LocalAddressType, WEB100_TYPE_INTEGER);
	ADD_RO_STATSVAR(PROC_CONN_READ, LocalAddress, WEB100_TYPE_INET_ADDRESS);
	ADD_RO_STATSVAR(PROC_CONN_READ, LocalPort, WEB100_TYPE_INET_PORT_NUMBER);
	ADD_RO_STATSVAR(PROC_CONN_READ, RemAddress, WEB100_TYPE_INET_ADDRESS);
	ADD_RO_STATSRENAME(PROC_CONN_READ, "_RemoteAddress", WEB100_TYPE_INET_ADDRESS, RemAddress);
	ADD_RO_STATSVAR(PROC_CONN_READ, RemPort, WEB100_TYPE_INET_PORT_NUMBER);
	ADD_RO_STATSRENAME(PROC_CONN_READ, "_RemotePort", WEB100_TYPE_INET_PORT_NUMBER, RemPort);
	
	ADD_RO_STATSVAR(PROC_CONN_READ, X_RcvRTT, WEB100_TYPE_GAUGE32);
	
	/* tune */
	add_var(web100_file_lookup(PROC_CONN_TUNE), "LimCwnd",
		WEB100_TYPE_GAUGE32, read_LimCwnd, 0,
		write_LimCwnd, 0);
	add_var(web100_file_lookup(PROC_CONN_TUNE), "LimRwin",
		WEB100_TYPE_GAUGE32, read_stats, OFFSET_ST(LimRwin),
		write_LimRwin, 0);
	add_var(web100_file_lookup(PROC_CONN_TUNE), "X_Sndbuf",
		WEB100_TYPE_GAUGE32, read_sk, OFFSET_SK(sk_sndbuf),
		write_Sndbuf, 0);
	add_var(web100_file_lookup(PROC_CONN_TUNE), "X_Rcvbuf",
		WEB100_TYPE_GAUGE32, read_sk, OFFSET_SK(sk_rcvbuf),
		write_Rcvbuf, 0);
	add_var(web100_file_lookup(PROC_CONN_TUNE), "State",
		WEB100_TYPE_INTEGER, read_stats, OFFSET_ST(State),
		write_State, 0);
#ifdef CONFIG_WEB100_NET100
	add_var(web100_file_lookup(PROC_CONN_TUNE), "CurMSS",
	        WEB100_TYPE_GAUGE32, read_stats, OFFSET_ST(CurMSS),
	        write_mss, 0);
#endif

#ifdef CONFIG_WEB100_NET100
	ADD_RW_STATSVAR(PROC_CONN_TUNE, WAD_IFQ, WEB100_TYPE_GAUGE32);
	ADD_RW_STATSVAR(PROC_CONN_TUNE, WAD_MaxBurst, WEB100_TYPE_GAUGE32);
	ADD_RW_STATSVAR(PROC_CONN_TUNE, WAD_MaxSsthresh, WEB100_TYPE_GAUGE32);
	ADD_RW_STATSVAR(PROC_CONN_TUNE, WAD_NoAI, WEB100_TYPE_INTEGER);
	add_var(web100_file_lookup(PROC_CONN_TUNE), "WAD_CwndAdjust",
	        WEB100_TYPE_INTEGER32, read_stats, OFFSET_ST(WAD_CwndAdjust),
	        write_CwndAdjust, 0);
#endif
}
