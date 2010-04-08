/*
 *	xt_MARK - Netfilter module to modify the NFMARK field of an skb
 *
 *	(C) 1999-2001 Marc Boucher <marc@mbsi.ca>
 *	Copyright © CC Computer Consultants GmbH, 2007 - 2008
 *	Jan Engelhardt <jengelh@computergmbh.de>
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License version 2 as
 *	published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <net/udp.h>
#include <net/checksum.h>
#include <net/route.h>
#include <net/inet_hashtables.h>
#include <net/net_namespace.h>

#include <net/netfilter/nf_conntrack.h>

#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/xt_MARK.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Marc Boucher <marc@mbsi.ca>");
MODULE_DESCRIPTION("Xtables: packet mark modification");
MODULE_ALIAS("ipt_MARK");
MODULE_ALIAS("ip6t_MARK");

extern DEFINE_PER_CPU(int, sknid_elevator);

static unsigned int
mark_tg_v0(struct sk_buff *skb, const struct net_device *in,
           const struct net_device *out, unsigned int hooknum,
           const struct xt_target *target, const void *targinfo)
{
	const struct xt_mark_target_info *markinfo = targinfo;

	skb->mark = markinfo->mark;
	return XT_CONTINUE;
}

static unsigned int
mark_tg_v1(struct sk_buff *skb, const struct net_device *in,
           const struct net_device *out, unsigned int hooknum,
           const struct xt_target *target, const void *targinfo)
{
	const struct xt_mark_target_info_v1 *markinfo = targinfo;
	int mark = 0;

	switch (markinfo->mode) {
	case XT_MARK_SET:
		mark = markinfo->mark;
		break;

	case XT_MARK_AND:
		mark = skb->mark & markinfo->mark;
		break;

	case XT_MARK_OR:
		mark = skb->mark | markinfo->mark;
		break;
	}

	skb->mark = mark;
	return XT_CONTINUE;
}

#define PEERCRED_SET(x) ((x!=0) && (x!=(unsigned int)-1)) 


static inline u_int16_t
get_dst_port(struct nf_conntrack_tuple *tuple)
{
	switch (tuple->dst.protonum) {
	case IPPROTO_GRE:
		/* XXX Truncate 32-bit GRE key to 16 bits */
		return tuple->dst.u.gre.key;
	case IPPROTO_ICMP:
		/* Bind on ICMP echo ID */
		return tuple->src.u.icmp.id;
	case IPPROTO_TCP:
		return tuple->dst.u.tcp.port;
	case IPPROTO_UDP:
		return tuple->dst.u.udp.port;
	default:
		return tuple->dst.u.all;
	}
}

static inline u_int16_t
get_src_port(struct nf_conntrack_tuple *tuple)
{
	switch (tuple->dst.protonum) {
	case IPPROTO_GRE:
		/* XXX Truncate 32-bit GRE key to 16 bits */
		return htons(ntohl(tuple->src.u.gre.key));
	case IPPROTO_ICMP:
		/* Bind on ICMP echo ID */
		return tuple->src.u.icmp.id;
	case IPPROTO_TCP:
		return tuple->src.u.tcp.port;
	case IPPROTO_UDP:
		return tuple->src.u.udp.port;
	default:
		return tuple->src.u.all;
	}
}

static struct sock *__udp4_lib_lookup(struct net *net, __be32 saddr,
		__be16 sport, __be32 daddr, __be16 dport,
		int dif, struct hlist_head udptable[])
{
	struct sock *sk, *result = NULL;
	struct hlist_node *node;
	unsigned short hnum = ntohs(dport);
	int badness = -1;

	read_lock(&udp_hash_lock);
	sk_for_each(sk, node, &udptable[udp_hashfn(net, hnum)]) {
		struct inet_sock *inet = inet_sk(sk);

		if (net_eq(sock_net(sk), net) && sk->sk_hash == hnum &&
				!ipv6_only_sock(sk)) {
			int score = (sk->sk_family == PF_INET ? 1 : 0);

			if (inet->rcv_saddr) {
				if (inet->rcv_saddr != daddr)
					continue;
				score+=2;
			} else {
				/* block non nx_info ips */
				if (!v4_addr_in_nx_info(sk->sk_nx_info,
					daddr, NXA_MASK_BIND))
					continue;
			}
			if (inet->daddr) {
				if (inet->daddr != saddr)
					continue;
				score+=2;
			}
			if (inet->dport) {
				if (inet->dport != sport)
					continue;
				score+=2;
			}
			if (sk->sk_bound_dev_if) {
				if (sk->sk_bound_dev_if != dif)
					continue;
				score+=2;
			}
			if (score == 9) {
				result = sk;
				break;
			} else if (score > badness) {
				result = sk;
				badness = score;
			}
		}
	}

	if (result)
		sock_hold(result);
	read_unlock(&udp_hash_lock);
	return result;
}

int onceonly = 1;

static unsigned int
mark_tg(struct sk_buff *skb, const struct net_device *in,
        const struct net_device *out, unsigned int hooknum,
        const struct xt_target *target, const void *targinfo)
{
	const struct xt_mark_tginfo2 *info = targinfo;
    long mark = -1;
    enum ip_conntrack_info ctinfo;
    struct sock *connection_sk;
    int dif;
    struct nf_conn *ct;
    extern struct inet_hashinfo tcp_hashinfo;
    enum ip_conntrack_dir dir;
    int *curtag;
    u_int32_t src_ip;
    u_int32_t dst_ip;
    u_int16_t proto, src_port;
    u_int32_t ip;
    u_int16_t port;

    
    if (info->mark == ~0U) {
        // As of 2.6.27.39, Dec 8 2009, 
        // NetNS + VNET = Trouble
        // Let's handle this as a special case
        struct net *net = dev_net(skb->dev);
        if (!net_eq(net, &init_net)) {
            WARN_ON(onceonly);
            onceonly = 0;
            return XT_CONTINUE;
        }

        /* copy-xid */
        dif = ((struct rtable *)(skb->dst))->rt_iif;

        ct = nf_ct_get(skb, &ctinfo);
        if (!ct) 
            goto out_mark_finish;

        dir = CTINFO2DIR(ctinfo);
        src_ip = ct->tuplehash[dir].tuple.src.u3.ip;
        dst_ip = ct->tuplehash[dir].tuple.dst.u3.ip;
        src_port = get_src_port(&ct->tuplehash[dir].tuple);
        proto = ct->tuplehash[dir].tuple.dst.protonum;

        ip = ct->tuplehash[dir].tuple.dst.u3.ip;
        port = get_dst_port(&ct->tuplehash[dir].tuple);

        if (proto == 1) {
            if (skb->mark > 0)
                /* The packet is marked, it's going out */
                ct->xid[0] = skb->mark;

            if (ct->xid[0] > 0)
                mark = ct->xid[0];
        }
        else if (proto == 17) {
            struct sock *sk;
            if (!skb->mark) {
                sk = __udp4_lib_lookup(net,src_ip, src_port,
                        ip, port, dif, udp_hash);

                if (sk && hooknum == NF_INET_LOCAL_IN)
                    mark = sk->sk_nid;

                if (sk)
                    sock_put(sk);
            }
            else if (skb->mark > 0)
                /* The packet is marked, it's going out */
                ct->xid[0] = skb->mark;
        }
        else if (proto == 6) /* TCP */{
            int sockettype = 0; /* Established socket */

            /* Looks for an established socket or a listening 
               socket corresponding to the 4-tuple, in that order.
               The order is important for Codemux connections
               to be handled properly */

            connection_sk = inet_lookup_established(net,
                    &tcp_hashinfo, src_ip, src_port, ip, port, dif);

            if (!connection_sk) {
                connection_sk = inet_lookup_listener(net,
                        &tcp_hashinfo, ip, port, dif);
                sockettype = 1; /* Listening socket */
            }

            if (connection_sk) {
                if (connection_sk->sk_state == TCP_TIME_WAIT) {
                    inet_twsk_put(inet_twsk(connection_sk));
                    goto out_mark_finish;
                }

                /* The peercred is not set. We set it if the other side has an xid. */
                if (!PEERCRED_SET(connection_sk->sk_peercred.uid)
                        && ct->xid[!dir] > 0 && (sockettype == 0)) {
                    connection_sk->sk_peercred.gid = 
                        connection_sk->sk_peercred.uid = ct->xid[!dir];
                }

                /* The peercred is set, and is not equal to the XID of 'the other side' */
                else if (PEERCRED_SET(connection_sk->sk_peercred.uid) &&
                        (connection_sk->sk_peercred.uid != ct->xid[!dir]) &&
                        (sockettype == 0)) {
                    mark = connection_sk->sk_peercred.uid;
                }

                /* Has this connection already been tagged? */
                if (ct->xid[dir] < 1) {
                    /* No - let's tag it */ 
                    ct->xid[dir]=connection_sk->sk_nid;
                }

                if (mark == -1 && (ct->xid[dir] != 0))
                    mark = ct->xid[dir];

                sock_put(connection_sk);
            }

            /* All else failed. Is this a connection over raw sockets?
               That explains why we couldn't get anything out of skb->sk,
               or look up a "real" connection. */
            if (ct->xid[dir] < 1) {
                if (skb->skb_tag)
                    ct->xid[dir] = skb->skb_tag;
            }

            /* Covers CoDemux case */
            if (mark < 1 && (ct->xid[dir] > 0))
                mark = ct->xid[dir];

            if (mark < 1 && (ct->xid[!dir] > 0))
                mark = ct->xid[!dir];
            goto out_mark_finish;
        }
    }
    else
        mark = (skb->mark & ~info->mask) ^ info->mark;

out_mark_finish:
    if (mark != -1)
        skb->mark = mark;

    curtag = &__get_cpu_var(sknid_elevator);
    if (mark > 0 && *curtag == -2 && hooknum == NF_INET_LOCAL_IN) 
        *curtag = mark;

	return XT_CONTINUE;
}

static bool
mark_tg_check_v0(const char *tablename, const void *entry,
                 const struct xt_target *target, void *targinfo,
                 unsigned int hook_mask)
{
	const struct xt_mark_target_info *markinfo = targinfo;

	if (markinfo->mark > 0xffffffff) {
		printk(KERN_WARNING "MARK: Only supports 32bit wide mark\n");
		return false;
	}
	return true;
}

static bool
mark_tg_check_v1(const char *tablename, const void *entry,
                 const struct xt_target *target, void *targinfo,
                 unsigned int hook_mask)
{
	const struct xt_mark_target_info_v1 *markinfo = targinfo;

	if (markinfo->mode != XT_MARK_SET
	    && markinfo->mode != XT_MARK_AND
	    && markinfo->mode != XT_MARK_OR) {
		printk(KERN_WARNING "MARK: unknown mode %u\n",
		       markinfo->mode);
		return false;
	}
	if (markinfo->mark > 0xffffffff) {
		printk(KERN_WARNING "MARK: Only supports 32bit wide mark\n");
		return false;
	}
	return true;
}

#ifdef CONFIG_COMPAT
struct compat_xt_mark_target_info {
	compat_ulong_t	mark;
};

static void mark_tg_compat_from_user_v0(void *dst, void *src)
{
	const struct compat_xt_mark_target_info *cm = src;
	struct xt_mark_target_info m = {
		.mark	= cm->mark,
	};
	memcpy(dst, &m, sizeof(m));
}

static int mark_tg_compat_to_user_v0(void __user *dst, void *src)
{
	const struct xt_mark_target_info *m = src;
	struct compat_xt_mark_target_info cm = {
		.mark	= m->mark,
	};
	return copy_to_user(dst, &cm, sizeof(cm)) ? -EFAULT : 0;
}

struct compat_xt_mark_target_info_v1 {
	compat_ulong_t	mark;
	u_int8_t	mode;
	u_int8_t	__pad1;
	u_int16_t	__pad2;
};

static void mark_tg_compat_from_user_v1(void *dst, void *src)
{
	const struct compat_xt_mark_target_info_v1 *cm = src;
	struct xt_mark_target_info_v1 m = {
		.mark	= cm->mark,
		.mode	= cm->mode,
	};
	memcpy(dst, &m, sizeof(m));
}

static int mark_tg_compat_to_user_v1(void __user *dst, void *src)
{
	const struct xt_mark_target_info_v1 *m = src;
	struct compat_xt_mark_target_info_v1 cm = {
		.mark	= m->mark,
		.mode	= m->mode,
	};
	return copy_to_user(dst, &cm, sizeof(cm)) ? -EFAULT : 0;
}
#endif /* CONFIG_COMPAT */

static struct xt_target mark_tg_reg[] __read_mostly = {
	{
		.name		= "MARK",
		.family		= AF_INET,
		.revision	= 0,
		.checkentry	= mark_tg_check_v0,
		.target		= mark_tg_v0,
		.targetsize	= sizeof(struct xt_mark_target_info),
#ifdef CONFIG_COMPAT
		.compatsize	= sizeof(struct compat_xt_mark_target_info),
		.compat_from_user = mark_tg_compat_from_user_v0,
		.compat_to_user	= mark_tg_compat_to_user_v0,
#endif
		.table		= "mangle",
		.me		= THIS_MODULE,
	},
	{
		.name		= "MARK",
		.family		= AF_INET,
		.revision	= 1,
		.checkentry	= mark_tg_check_v1,
		.target		= mark_tg_v1,
		.targetsize	= sizeof(struct xt_mark_target_info_v1),
#ifdef CONFIG_COMPAT
		.compatsize	= sizeof(struct compat_xt_mark_target_info_v1),
		.compat_from_user = mark_tg_compat_from_user_v1,
		.compat_to_user	= mark_tg_compat_to_user_v1,
#endif
		.table		= "mangle",
		.me		= THIS_MODULE,
	},
	{
		.name		= "MARK",
		.family		= AF_INET6,
		.revision	= 0,
		.checkentry	= mark_tg_check_v0,
		.target		= mark_tg_v0,
		.targetsize	= sizeof(struct xt_mark_target_info),
#ifdef CONFIG_COMPAT
		.compatsize	= sizeof(struct compat_xt_mark_target_info),
		.compat_from_user = mark_tg_compat_from_user_v0,
		.compat_to_user	= mark_tg_compat_to_user_v0,
#endif
		.table		= "mangle",
		.me		= THIS_MODULE,
	},
	{
		.name		= "MARK",
		.family		= AF_INET6,
		.revision	= 1,
		.checkentry	= mark_tg_check_v1,
		.target		= mark_tg_v1,
		.targetsize	= sizeof(struct xt_mark_target_info_v1),
#ifdef CONFIG_COMPAT
		.compatsize	= sizeof(struct compat_xt_mark_target_info_v1),
		.compat_from_user = mark_tg_compat_from_user_v1,
		.compat_to_user	= mark_tg_compat_to_user_v1,
#endif
		.table		= "mangle",
		.me		= THIS_MODULE,
	},
	{
		.name           = "MARK",
		.revision       = 2,
		.family         = AF_INET,
		.target         = mark_tg,
		.targetsize     = sizeof(struct xt_mark_tginfo2),
		.me             = THIS_MODULE,
	},
	{
		.name           = "MARK",
		.revision       = 2,
		.family         = AF_INET6,
		.target         = mark_tg,
		.targetsize     = sizeof(struct xt_mark_tginfo2),
		.me             = THIS_MODULE,
	},
};

static int __init mark_tg_init(void)
{
	return xt_register_targets(mark_tg_reg, ARRAY_SIZE(mark_tg_reg));
}

static void __exit mark_tg_exit(void)
{
	xt_unregister_targets(mark_tg_reg, ARRAY_SIZE(mark_tg_reg));
}

module_init(mark_tg_init);
module_exit(mark_tg_exit);
