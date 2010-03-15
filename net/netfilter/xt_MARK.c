/* This is a module which is used for setting the NFMARK field of an skb. */

/* (C) 1999-2001 Marc Boucher <marc@mbsi.ca>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#include <linux/module.h>
#include <linux/version.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <net/udp.h>
#include <net/checksum.h>
#include <net/route.h>
#include <net/inet_hashtables.h>

#include <net/netfilter/nf_conntrack.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/xt_MARK.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Marc Boucher <marc@mbsi.ca>");
MODULE_DESCRIPTION("ip[6]tables MARK modification module");
MODULE_ALIAS("ipt_MARK");
MODULE_ALIAS("ip6t_MARK");

#define PEERCRED_SET(x) ((x!=0) && (x!=(unsigned int)-1)) 

static inline u_int16_t
get_dst_port(struct nf_conntrack_tuple *tuple)
{
	switch (tuple->dst.protonum) {
	case IPPROTO_GRE:
		/* XXX Truncate 32-bit GRE key to 16 bits */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,11)
		return tuple->dst.u.gre.key;
#else
		return htons(ntohl(tuple->dst.u.gre.key));
#endif  
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

static unsigned int
target_v0(struct sk_buff **pskb,
	  const struct net_device *in,
	  const struct net_device *out,
	  unsigned int hooknum,
	  const struct xt_target *target,
	  const void *targinfo)
{
	const struct xt_mark_target_info *markinfo = targinfo;

	(*pskb)->mark = markinfo->mark;
	return XT_CONTINUE;
}

extern DEFINE_PER_CPU(int, sknid_elevator);

static struct sock *__udp4_lib_lookup(__be32 saddr, __be16 sport,
                      __be32 daddr, __be16 dport,
                      int dif, struct hlist_head udptable[])
{
    struct sock *sk, *result = NULL;
    struct hlist_node *node;
    unsigned short hnum = ntohs(dport);
    int badness = -1;

    read_lock(&udp_hash_lock);

    sk_for_each(sk, node, &udptable[hnum & (UDP_HTABLE_SIZE - 1)]) {
        struct inet_sock *inet = inet_sk(sk);

        if (sk->sk_hash == hnum && !ipv6_only_sock(sk)) {
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

#define related(ct) (ct==(IP_CT_IS_REPLY + IP_CT_RELATED))

static unsigned int
target_v1(struct sk_buff **pskb,
	  const struct net_device *in,
	  const struct net_device *out,
	  unsigned int hooknum,
	  const struct xt_target *target,
	  const void *targinfo)
{
	const struct xt_mark_target_info_v1 *markinfo = targinfo;
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

		int mark = -1;

	switch (markinfo->mode) {
	case XT_MARK_SET:
		mark = markinfo->mark;
		break;

	case XT_MARK_AND:
		mark = (*pskb)->mark & markinfo->mark;
		break;

	case XT_MARK_OR:
		mark = (*pskb)->mark | markinfo->mark;
		break;

				case XT_MARK_COPYXID: 
						dif = ((struct rtable *)(*pskb)->dst)->rt_iif;

						ct = nf_ct_get((*pskb), &ctinfo);
						if (!ct) 
								break;

						dir = CTINFO2DIR(ctinfo);
						src_ip = ct->tuplehash[dir].tuple.src.u3.ip;
						dst_ip = ct->tuplehash[dir].tuple.dst.u3.ip;
						src_port = get_src_port(&ct->tuplehash[dir].tuple);
						proto = ct->tuplehash[dir].tuple.dst.protonum;

						ip = ct->tuplehash[dir].tuple.dst.u3.ip;
						port = get_dst_port(&ct->tuplehash[dir].tuple);

						if (proto == 1) {
								if ((*pskb)->mark>0) /* The packet is marked, it's going out */
								{
										ct->xid[0]=(*pskb)->mark;
								}

								if (ct->xid[0] > 0) {
										mark = ct->xid[0];
								}
						}
						else if (proto == 17) {
								struct sock *sk;
								if (!(*pskb)->mark) {
										sk = __udp4_lib_lookup(src_ip, src_port, ip, port,
														dif, udp_hash);

										if (sk && hooknum==NF_IP_LOCAL_IN) {
												mark=sk->sk_nid;
										}

										if (sk) {
												sock_put(sk);
										}
								}
								else
										if ((*pskb)->mark>0) /* The packet is marked, it's going out */
										{
												ct->xid[0]=(*pskb)->mark;
										}
						}
						else if (proto == 6) /* TCP */{
								int sockettype=0; /* Established socket */
								/* Looks for an established socket or a listening socket corresponding to the 4-tuple, in
								 * that order. The order is important for Codemux connections to be handled properly */

								connection_sk = inet_lookup_established(&tcp_hashinfo, src_ip, src_port, ip, port, dif);

								if (!connection_sk) {
										connection_sk = inet_lookup_listener(&tcp_hashinfo, ip, port, dif);
										sockettype=1; /* Listening socket */
								}

								if (connection_sk) {
										/* The peercred is not set. We set it if the other side has an xid. */
										if (!PEERCRED_SET(connection_sk->sk_peercred.uid)
														&& ct->xid[!dir]>0 && (sockettype==0)) {
												connection_sk->sk_peercred.gid = connection_sk->sk_peercred.uid = ct->xid[!dir];
										}

										/* The peercred is set, and is not equal to the XID of 'the other side' */
										else if (PEERCRED_SET(connection_sk->sk_peercred.uid) && (connection_sk->sk_peercred.uid != ct->xid[!dir]) && (sockettype==0)) {
												mark = connection_sk->sk_peercred.uid;
										}

										/* Has this connection already been tagged? */
										if (ct->xid[dir] < 1) {
												/* No - let's tag it */ 
												ct->xid[dir]=connection_sk->sk_nid;

										}

										if (mark==-1 && (ct->xid[dir]!= 0))
												mark = ct->xid[dir];

										if (connection_sk->sk_state == TCP_TIME_WAIT) {
												inet_twsk_put(inet_twsk(connection_sk));
												break;
										}
										else
												sock_put(connection_sk);
	}

								/* All else failed. Is this a connection over raw sockets? That explains
								 * why we couldn't get anything out of skb->sk, or look up a "real" connection.*/
								if (ct->xid[dir]<1) {
										if ((*pskb)->skb_tag) {
												ct->xid[dir]=(*pskb)->skb_tag;
										}
								}

								/* Covers CoDemux case */
								if (mark < 1 && (ct->xid[dir]>0)) {
										mark = ct->xid[dir];
								}

								if (mark < 1 && (ct->xid[!dir]>0)) {
										mark = ct->xid[!dir];
								}
								break;
						}
		}
		if (mark != -1) {
	(*pskb)->mark = mark;
		}

		curtag=&__get_cpu_var(sknid_elevator);
		if (mark > 0 && *curtag==-2 && hooknum==NF_IP_LOCAL_IN) 
		{
				*curtag = mark;
		}
	return XT_CONTINUE;
}

static int
checkentry_v0(const char *tablename,
	      const void *entry,
	      const struct xt_target *target,
	      void *targinfo,
	      unsigned int hook_mask)
{
	struct xt_mark_target_info *markinfo = targinfo;

	if (markinfo->mark > 0xffffffff) {
		printk(KERN_WARNING "MARK: Only supports 32bit wide mark\n");
		return 0;
	}
	return 1;
}

static int
checkentry_v1(const char *tablename,
	      const void *entry,
	      const struct xt_target *target,
	      void *targinfo,
	      unsigned int hook_mask)
{
	struct xt_mark_target_info_v1 *markinfo = targinfo;

	if (markinfo->mode != XT_MARK_SET
	    && markinfo->mode != XT_MARK_AND
	    && markinfo->mode != XT_MARK_OR
	    && markinfo->mode != XT_MARK_COPYXID) {
		printk(KERN_WARNING "MARK: unknown mode %u\n",
		       markinfo->mode);
		return 0;
	}
	if (markinfo->mark > 0xffffffff) {
		printk(KERN_WARNING "MARK: Only supports 32bit wide mark\n");
		return 0;
	}
	return 1;
}

#ifdef CONFIG_COMPAT
struct compat_xt_mark_target_info_v1 {
	compat_ulong_t	mark;
	u_int8_t	mode;
	u_int8_t	__pad1;
	u_int16_t	__pad2;
};

static void compat_from_user_v1(void *dst, void *src)
{
	struct compat_xt_mark_target_info_v1 *cm = src;
	struct xt_mark_target_info_v1 m = {
		.mark	= cm->mark,
		.mode	= cm->mode,
	};
	memcpy(dst, &m, sizeof(m));
}

static int compat_to_user_v1(void __user *dst, void *src)
{
	struct xt_mark_target_info_v1 *m = src;
	struct compat_xt_mark_target_info_v1 cm = {
		.mark	= m->mark,
		.mode	= m->mode,
	};
	return copy_to_user(dst, &cm, sizeof(cm)) ? -EFAULT : 0;
}
#endif /* CONFIG_COMPAT */

static struct xt_target xt_mark_target[] = {
	{
		.name		= "MARK",
		.family		= AF_INET,
		.revision	= 0,
		.checkentry	= checkentry_v0,
		.target		= target_v0,
		.targetsize	= sizeof(struct xt_mark_target_info),
		.table		= "mangle",
		.me		= THIS_MODULE,
	},
	{
		.name		= "MARK",
		.family		= AF_INET,
		.revision	= 1,
		.checkentry	= checkentry_v1,
		.target		= target_v1,
		.targetsize	= sizeof(struct xt_mark_target_info_v1),
#ifdef CONFIG_COMPAT
		.compatsize	= sizeof(struct compat_xt_mark_target_info_v1),
		.compat_from_user = compat_from_user_v1,
		.compat_to_user	= compat_to_user_v1,
#endif
		.table		= "mangle",
		.me		= THIS_MODULE,
	},
	{
		.name		= "MARK",
		.family		= AF_INET6,
		.revision	= 0,
		.checkentry	= checkentry_v0,
		.target		= target_v0,
		.targetsize	= sizeof(struct xt_mark_target_info),
		.table		= "mangle",
		.me		= THIS_MODULE,
	},
};

static int __init xt_mark_init(void)
{
	return xt_register_targets(xt_mark_target, ARRAY_SIZE(xt_mark_target));
}

static void __exit xt_mark_fini(void)
{
	xt_unregister_targets(xt_mark_target, ARRAY_SIZE(xt_mark_target));
}

module_init(xt_mark_init);
module_exit(xt_mark_fini);
