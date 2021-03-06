/*
 *	Linux NET3:	GRE over IP protocol decoder.
 *
 *	Authors: Alexey Kuznetsov (kuznet@ms2.inr.ac.ru)
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 *
 */

#include <linux/capability.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <asm/uaccess.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_arp.h>
#include <linux/mroute.h>
#include <linux/init.h>
#include <linux/in6.h>
#include <linux/inetdevice.h>
#include <linux/etherdevice.h>   /**XXX added XXX */
#include <linux/igmp.h>
#include <linux/netfilter_ipv4.h>
#include <linux/if_ether.h>

#include <net/sock.h>
#include <net/ip.h>
#include <net/icmp.h>
#include <net/protocol.h>
#include <net/ipip.h>
#include <net/arp.h>
#include <net/checksum.h>
#include <net/dsfield.h>
#include <net/inet_ecn.h>
#include <net/xfrm.h>

#ifdef CONFIG_IPV6
#include <net/ipv6.h>
#include <net/ip6_fib.h>
#include <net/ip6_route.h>
#endif

#define ipv4_is_multicast(x)    (((x) & htonl(0xf0000000)) == htonl(0xe0000000))

//#define GRE_DEBUG 1

/*
   Problems & solutions
   --------------------

   1. The most important issue is detecting local dead loops.
   They would cause complete host lockup in transmit, which
   would be "resolved" by stack overflow or, if queueing is enabled,
   with infinite looping in net_bh.

   We cannot track such dead loops during route installation,
   it is infeasible task. The most general solutions would be
   to keep skb->encapsulation counter (sort of local ttl),
   and silently drop packet when it expires. It is the best
   solution, but it supposes maintaing new variable in ALL
   skb, even if no tunneling is used.

   Current solution: t->recursion lock breaks dead loops. It looks
   like dev->tbusy flag, but I preferred new variable, because
   the semantics is different. One day, when hard_start_xmit
   will be multithreaded we will have to use skb->encapsulation.



   2. Networking dead loops would not kill routers, but would really
   kill network. IP hop limit plays role of "t->recursion" in this case,
   if we copy it from packet being encapsulated to upper header.
   It is very good solution, but it introduces two problems:

   - Routing protocols, using packets with ttl=1 (OSPF, RIP2),
     do not work over tunnels.
   - traceroute does not work. I planned to relay ICMP from tunnel,
     so that this problem would be solved and traceroute output
     would even more informative. This idea appeared to be wrong:
     only Linux complies to rfc1812 now (yes, guys, Linux is the only
     true router now :-)), all routers (at least, in neighbourhood of mine)
     return only 8 bytes of payload. It is the end.

   Hence, if we want that OSPF worked or traceroute said something reasonable,
   we should search for another solution.

   One of them is to parse packet trying to detect inner encapsulation
   made by our node. It is difficult or even impossible, especially,
   taking into account fragmentation. TO be short, tt is not solution at all.

   Current solution: The solution was UNEXPECTEDLY SIMPLE.
   We force DF flag on tunnels with preconfigured hop limit,
   that is ALL. :-) Well, it does not remove the problem completely,
   but exponential growth of network traffic is changed to linear
   (branches, that exceed pmtu are pruned) and tunnel mtu
   fastly degrades to value <68, where looping stops.
   Yes, it is not good if there exists a router in the loop,
   which does not force DF, even when encapsulating packets have DF set.
   But it is not our problem! Nobody could accuse us, we made
   all that we could make. Even if it is your gated who injected
   fatal route to network, even if it were you who configured
   fatal static route: you are innocent. :-)



   3. Really, ipv4/ipip.c, ipv4/ip_gre.c and ipv6/sit.c contain
   practically identical code. It would be good to glue them
   together, but it is not very evident, how to make them modular.
   sit is integral part of IPv6, ipip and gre are naturally modular.
   We could extract common parts (hash table, ioctl etc)
   to a separate module (ip_tunnel.c).

   Alexey Kuznetsov.
 */

static int ipgre_tunnel_init(struct net_device *dev);
static void ipgre_ip_tunnel_setup(struct net_device *dev);
static void ipgre_eth_tunnel_setup(struct net_device *dev);

/* Fallback tunnel: no source, no destination, no key, no options */

static int ipgre_fb_tunnel_init(struct net_device *dev);

static struct net_device *ipgre_fb_tunnel_dev;

/* Tunnel hash table */

/*
   4 hash tables:

   3: (remote,local)
   2: (remote,*)
   1: (*,local)
   0: (*,*)

   We require exact key match i.e. if a key is present in packet
   it will match only tunnel with the same key; if it is not present,
   it will match only keyless tunnel.

   All keysless packets, if not matched configured keyless tunnels
   will match fallback tunnel.
 */

#define HASH_SIZE  1024
#define HASH(addr) (ntohl(addr)&1023)

static struct ip_tunnel *tunnels[4][HASH_SIZE];

#define tunnels_r_l	(tunnels[3])
#define tunnels_r	(tunnels[2])
#define tunnels_l	(tunnels[1])
#define tunnels_wc	(tunnels[0])

static DEFINE_RWLOCK(ipgre_lock);

/* Given src, dst and key, find appropriate for input tunnel. */

static struct ip_tunnel * ipgre_tunnel_lookup(__be32 remote, __be32 local, __be32 key)
{
	/* HACK */
	unsigned hash_value = HASH(key);
	struct ip_tunnel *t;

	t = tunnels_r_l[hash_value];

	if (t && (t->parms.i_key == key) && (t->dev->flags&IFF_UP)) {
		return t;
	}

	t = tunnels_r[hash_value];
			if (t && (t->parms.i_key == key) && (t->dev->flags&IFF_UP))
				return t;

	t = tunnels_l[hash_value];
			if (t && (t->parms.i_key == key) && (t->dev->flags&IFF_UP))
				return t;
	t = tunnels_wc[hash_value];
		if (t && (t->parms.i_key == key) && (t->dev->flags&IFF_UP))
			return t;
	if (ipgre_fb_tunnel_dev->flags&IFF_UP)
		return netdev_priv(ipgre_fb_tunnel_dev);
	return NULL;
}

static struct ip_tunnel **ipgre_bucket(struct ip_tunnel *t)
{
	__be32 remote = t->parms.iph.daddr;
	__be32 local = t->parms.iph.saddr;
	__be32 key = t->parms.i_key;
	unsigned h = HASH(key);
	int prio = 0;

	if (local)
		prio |= 1;
	if (remote && !ipv4_is_multicast(remote)) {
		prio |= 2;
		//h ^= HASH(remote);
	}

	return &tunnels[prio][h];
}

static void ipgre_tunnel_link(struct ip_tunnel *t)
{
	struct ip_tunnel **tp = ipgre_bucket(t);

	t->next = *tp;
	write_lock_bh(&ipgre_lock);
	*tp = t;
	write_unlock_bh(&ipgre_lock);
}

static void ipgre_tunnel_unlink(struct ip_tunnel *t)
{
	struct ip_tunnel **tp;

	for (tp = ipgre_bucket(t); *tp; tp = &(*tp)->next) {
		if (t == *tp) {
			write_lock_bh(&ipgre_lock);
			*tp = t->next;
			write_unlock_bh(&ipgre_lock);
			break;
		}
	}
}

static struct ip_tunnel * ipgre_tunnel_locate(struct ip_tunnel_parm *parms, int create)
{
	__be32 remote = parms->iph.daddr;
	__be32 local = parms->iph.saddr;
	__be32 key = parms->i_key;
	__be16 proto = parms->proto_type;
	struct ip_tunnel *t, **tp, *nt;
	struct net_device *dev;
	unsigned h = HASH(key);
	int prio = 0;
	char name[IFNAMSIZ];

	if (local)
		prio |= 1;
	if (remote && !ipv4_is_multicast(remote)) {
		prio |= 2;
		//h ^= HASH(remote);
	}
	for (tp = &tunnels[prio][h]; (t = *tp) != NULL; tp = &t->next) {
		if (local == t->parms.iph.saddr && remote == t->parms.iph.daddr) {
			if (key == t->parms.i_key)
				return t;
		}
	}
	if (!create)
		return NULL;

	printk(KERN_CRIT "Adding tunnel %s with key %d\n", parms->name, ntohl(key));

	if (parms->name[0])
		strlcpy(name, parms->name, IFNAMSIZ);
	else {
		int i;
		for (i=1; i<100; i++) {
			sprintf(name, "gre%d", i);
			if (__dev_get_by_name(&init_net, name) == NULL)
				break;
		}
		if (i==100)
			goto failed;
	}
	
	/* Tunnel creation: check payload type and call appropriate
	 * function */
	switch (proto)
	{
	    case ETH_P_IP:
		dev = alloc_netdev(sizeof(*t), name, ipgre_ip_tunnel_setup);
		break;
	    case ETH_P_ETH:
		dev = alloc_netdev(sizeof(*t), name, ipgre_eth_tunnel_setup);
		break;
	    default:
		return NULL;
	}

	if (!dev)
	  return NULL;

	dev->init = ipgre_tunnel_init;
	nt = netdev_priv(dev);
	nt->parms = *parms;

	if (register_netdevice(dev) < 0) {
		free_netdev(dev);
		goto failed;
	}

	dev_hold(dev);
	ipgre_tunnel_link(nt);
	return nt;

failed:
	return NULL;
}

static void ipgre_tunnel_uninit(struct net_device *dev)
{
	ipgre_tunnel_unlink(netdev_priv(dev));
	dev_put(dev);
}


static void ipgre_err(struct sk_buff *skb, u32 info)
{
#ifndef I_WISH_WORLD_WERE_PERFECT

/* It is not :-( All the routers (except for Linux) return only
   8 bytes of packet payload. It means, that precise relaying of
   ICMP in the real Internet is absolutely infeasible.

   Moreover, Cisco "wise men" put GRE key to the third word
   in GRE header. It makes impossible maintaining even soft state for keyed
   GRE tunnels with enabled checksum. Tell them "thank you".

   Well, I wonder, rfc1812 was written by Cisco employee,
   what the hell these idiots break standrads established
   by themself???
 */

	struct iphdr *iph = (struct iphdr*)skb->data;
	__be16	     *p = (__be16*)(skb->data+(iph->ihl<<2));
	int grehlen = (iph->ihl<<2) + 4;
	int type = icmp_hdr(skb)->type;
	int code = icmp_hdr(skb)->code;
	struct ip_tunnel *t;
	__be16 flags;

	flags = p[0];
	if (flags&(GRE_CSUM|GRE_KEY|GRE_SEQ|GRE_ROUTING|GRE_VERSION)) {
		if (flags&(GRE_VERSION|GRE_ROUTING))
			return;
		if (flags&GRE_KEY) {
			grehlen += 4;
			if (flags&GRE_CSUM)
				grehlen += 4;
		}
	}

	/* If only 8 bytes returned, keyed message will be dropped here */
	if (skb_headlen(skb) < grehlen)
		return;

	switch (type) {
	default:
	case ICMP_PARAMETERPROB:
		return;

	case ICMP_DEST_UNREACH:
		switch (code) {
		case ICMP_SR_FAILED:
		case ICMP_PORT_UNREACH:
			/* Impossible event. */
			return;
		case ICMP_FRAG_NEEDED:
			/* Soft state for pmtu is maintained by IP core. */
			return;
		default:
			/* All others are translated to HOST_UNREACH.
			   rfc2003 contains "deep thoughts" about NET_UNREACH,
			   I believe they are just ether pollution. --ANK
			 */
			break;
		}
		break;
	case ICMP_TIME_EXCEEDED:
		if (code != ICMP_EXC_TTL)
			return;
		break;
	}

	read_lock(&ipgre_lock);
	t = ipgre_tunnel_lookup(iph->daddr, iph->saddr, (flags&GRE_KEY) ? *(((__be32*)p) + (grehlen>>2) - 1) : 0);
	if (t == NULL || t->parms.iph.daddr == 0 || ipv4_is_multicast(t->parms.iph.daddr))
		goto out;

	if (t->parms.iph.ttl == 0 && type == ICMP_TIME_EXCEEDED)
		goto out;

	if (jiffies - t->err_time < IPTUNNEL_ERR_TIMEO)
		t->err_count++;
	else
		t->err_count = 1;
	t->err_time = jiffies;
out:
	read_unlock(&ipgre_lock);
	return;
#else
	struct iphdr *iph = (struct iphdr*)dp;
	struct iphdr *eiph;
	__be16	     *p = (__be16*)(dp+(iph->ihl<<2));
	int type = skb->h.icmph->type;
	int code = skb->h.icmph->code;
	int rel_type = 0;
	int rel_code = 0;
	__be32 rel_info = 0;
	__u32 n = 0;
	__be16 flags;
	int grehlen = (iph->ihl<<2) + 4;
	struct sk_buff *skb2;
	struct flowi fl;
	struct rtable *rt;

	if (skb->dev->nd_net != &init_net)
		return;

	if (p[1] != htons(ETH_P_IP))
		return;

	flags = p[0];
	if (flags&(GRE_CSUM|GRE_KEY|GRE_SEQ|GRE_ROUTING|GRE_VERSION)) {
		if (flags&(GRE_VERSION|GRE_ROUTING))
			return;
		if (flags&GRE_CSUM)
			grehlen += 4;
		if (flags&GRE_KEY)
			grehlen += 4;
		if (flags&GRE_SEQ)
			grehlen += 4;
	}
	if (len < grehlen + sizeof(struct iphdr))
		return;
	eiph = (struct iphdr*)(dp + grehlen);

	switch (type) {
	default:
		return;
	case ICMP_PARAMETERPROB:
		n = ntohl(skb->h.icmph->un.gateway) >> 24;
		if (n < (iph->ihl<<2))
			return;

		/* So... This guy found something strange INSIDE encapsulated
		   packet. Well, he is fool, but what can we do ?
		 */
		rel_type = ICMP_PARAMETERPROB;
		n -= grehlen;
		rel_info = htonl(n << 24);
		break;

	case ICMP_DEST_UNREACH:
		switch (code) {
		case ICMP_SR_FAILED:
		case ICMP_PORT_UNREACH:
			/* Impossible event. */
			return;
		case ICMP_FRAG_NEEDED:
			/* And it is the only really necessary thing :-) */
			n = ntohs(skb->h.icmph->un.frag.mtu);
			if (n < grehlen+68)
				return;
			n -= grehlen;
			/* BSD 4.2 MORE DOES NOT EXIST IN NATURE. */
			if (n > ntohs(eiph->tot_len))
				return;
			rel_info = htonl(n);
			break;
		default:
			/* All others are translated to HOST_UNREACH.
			   rfc2003 contains "deep thoughts" about NET_UNREACH,
			   I believe, it is just ether pollution. --ANK
			 */
			rel_type = ICMP_DEST_UNREACH;
			rel_code = ICMP_HOST_UNREACH;
			break;
		}
		break;
	case ICMP_TIME_EXCEEDED:
		if (code != ICMP_EXC_TTL)
			return;
		break;
	}

	/* Prepare fake skb to feed it to icmp_send */
	skb2 = skb_clone(skb, GFP_ATOMIC);
	if (skb2 == NULL)
		return;
	dst_release(skb2->dst);
	skb2->dst = NULL;
	skb_pull(skb2, skb->data - (u8*)eiph);
	skb_reset_network_header(skb2);

	/* Try to guess incoming interface */
	memset(&fl, 0, sizeof(fl));
	//fl.fl_net = &init_net;
	fl.fl4_dst = eiph->saddr;
	fl.fl4_tos = RT_TOS(eiph->tos);
	fl.proto = IPPROTO_GRE;
	if (ip_route_output_key(dev_net(dev),&rt, &fl)) {
		kfree_skb(skb2);
		return;
	}
	skb2->dev = rt->u.dst.dev;

	/* route "incoming" packet */
	if (rt->rt_flags&RTCF_LOCAL) {
		ip_rt_put(rt);
		rt = NULL;
		fl.fl4_dst = eiph->daddr;
		fl.fl4_src = eiph->saddr;
		fl.fl4_tos = eiph->tos;
		if (ip_route_output_key(&rt, &fl) ||
		    rt->u.dst.dev->type != ARPHRD_IPGRE) {
			ip_rt_put(rt);
			kfree_skb(skb2);
			return;
		}
	} else {
		ip_rt_put(rt);
		if (ip_route_input(skb2, eiph->daddr, eiph->saddr, eiph->tos, skb2->dev) ||
		    skb2->dst->dev->type != ARPHRD_IPGRE) {
			kfree_skb(skb2);
			return;
		}
	}

	/* change mtu on this route */
	if (type == ICMP_DEST_UNREACH && code == ICMP_FRAG_NEEDED) {
		if (n > dst_mtu(skb2->dst)) {
			kfree_skb(skb2);
			return;
		}
		skb2->dst->ops->update_pmtu(skb2->dst, n);
	} else if (type == ICMP_TIME_EXCEEDED) {
		struct ip_tunnel *t = netdev_priv(skb2->dev);
		if (t->parms.iph.ttl) {
			rel_type = ICMP_DEST_UNREACH;
			rel_code = ICMP_HOST_UNREACH;
		}
	}

	icmp_send(skb2, rel_type, rel_code, rel_info);
	kfree_skb(skb2);
#endif
}

static inline void ipgre_ecn_decapsulate(struct iphdr *iph, struct sk_buff *skb)
{
	if (INET_ECN_is_ce(iph->tos)) {
		if (skb->protocol == htons(ETH_P_IP)) {
			IP_ECN_set_ce(ip_hdr(skb));
		} else if (skb->protocol == htons(ETH_P_IPV6)) {
			IP6_ECN_set_ce(ipv6_hdr(skb));
		}
	}
}

static inline u8
ipgre_ecn_encapsulate(u8 tos, struct iphdr *old_iph, struct sk_buff *skb)
{
	u8 inner = 0;
	if (skb->protocol == htons(ETH_P_IP))
		inner = old_iph->tos;
	else if (skb->protocol == htons(ETH_P_IPV6))
		inner = ipv6_get_dsfield((struct ipv6hdr *)old_iph);
	return INET_ECN_encapsulate(tos, inner);
}

static int ipgre_rcv(struct sk_buff *skb)
{
	struct iphdr *iph;
	u8     *h;
	__be16    flags;
	__sum16   csum = 0;
	__be32 key = 0;
	u32    seqno = 0;
	struct ip_tunnel *tunnel;
	int    offset = 4;
	__be16 proto;

	if (skb->dev->nd_net != &init_net) {
		kfree_skb(skb);
		return 0;
	}
	if (!pskb_may_pull(skb, 16))
		goto drop_nolock;

	iph = ip_hdr(skb);
	h = skb->data;
	flags = *(__be16*)h;

#ifdef GRE_DEBUG
	printk(KERN_DEBUG "gre.c [601] src:%x dst:%x  proto:%d %x", iph->saddr, iph->daddr, iph->protocol, skb->data);
#endif	
	proto = ntohs(*(__be16*)(h+2)); /* XXX added XXX */
	
	if (flags&(GRE_CSUM|GRE_KEY|GRE_ROUTING|GRE_SEQ|GRE_VERSION)) {
		/* - Version must be 0.
		   - We do not support routing headers.
		 */
		if (flags&(GRE_VERSION|GRE_ROUTING))
			goto drop_nolock;

		if (flags&GRE_CSUM) {
			switch (skb->ip_summed) {
			case CHECKSUM_COMPLETE:
				csum = csum_fold(skb->csum);
				if (!csum)
					break;
				/* fall through */
			case CHECKSUM_NONE:
				skb->csum = 0;
				csum = __skb_checksum_complete(skb);
				skb->ip_summed = CHECKSUM_COMPLETE;
			}
			offset += 4;
		}
		if (flags&GRE_KEY) {
			key = *(__be32*)(h + offset);
			offset += 4;
		}
		if (flags&GRE_SEQ) {
			seqno = ntohl(*(__be32*)(h + offset));
			offset += 4;
		}
	}

	read_lock(&ipgre_lock);
	if ((tunnel = ipgre_tunnel_lookup(iph->saddr, iph->daddr, key)) != NULL) {
		secpath_reset(skb);

		skb->protocol = *(__be16*)(h + 2);
		/* WCCP version 1 and 2 protocol decoding.
		 * - Change protocol to IP
		 * - When dealing with WCCPv2, Skip extra 4 bytes in GRE header
		 */
		if (flags == 0 &&
		    skb->protocol == htons(ETH_P_WCCP)) {
			skb->protocol = htons(ETH_P_IP);
			if ((*(h + offset) & 0xF0) != 0x40)
				offset += 4;
		}

		//skb->mac.raw = skb->nh.raw;
		skb_reset_mac_header(skb);
		__pskb_pull(skb, offset);
		skb_reset_network_header(skb);
		skb_postpull_rcsum(skb, skb_transport_header(skb), offset);
		if(proto == ETH_P_ETH)
		  {
#ifdef GRE_DEBUG
		    unsigned char* tmp_hdr = skb->data;
		    printk(KERN_DEBUG "gre.c [658] %x %x %x %x %x %x\tskb %x\n", tmp_hdr[0], tmp_hdr[1], tmp_hdr[2], tmp_hdr[3], tmp_hdr[4], tmp_hdr[5], skb->data);
#endif		    
		    skb->protocol = eth_type_trans(skb, tunnel->dev);

		    /* XXX added these lines to make arp work? XXX */
 		    /*skb->mac.raw = skb->data;*/
 		    skb->network_header = skb->network_header + ETH_HLEN;
		    /* XXX added these lines to make arp work? XXX */

#ifdef GRE_DEBUG
		    tmp_hdr = skb->data;
		    printk(KERN_DEBUG "gre.c [669] %x %x %x %x %x %x\tskb %x\n", tmp_hdr[0], tmp_hdr[1], tmp_hdr[2], tmp_hdr[3], tmp_hdr[4], tmp_hdr[5], skb->data);
 		    printk(KERN_ALERT "gre.c [671] received ethernet on gre %x %x\n",skb->protocol, ((skb->nh).iph)->protocol); 
#endif
		    memset(&(IPCB(skb)->opt), 0, sizeof(struct ip_options));
		  }
		else
		  skb->pkt_type = PACKET_HOST;
#ifdef CONFIG_NET_IPGRE_BROADCAST
		if (ipv4_is_multicast(iph->daddr)) {
			/* Looped back packet, drop it! */
			if (((struct rtable*)skb->dst)->fl.iif == 0)
				goto drop;
			tunnel->dev->stats.multicast++;
			skb->pkt_type = PACKET_BROADCAST;
		}
#endif

		if (((flags&GRE_CSUM) && csum) ||
		    (!(flags&GRE_CSUM) && tunnel->parms.i_flags&GRE_CSUM)) {
			tunnel->dev->stats.rx_crc_errors++;
			tunnel->dev->stats.rx_errors++;
			goto drop;
		}
		if (tunnel->parms.i_flags&GRE_SEQ) {
			if (!(flags&GRE_SEQ) ||
			    (tunnel->i_seqno && (s32)(seqno - tunnel->i_seqno) < 0)) {
				tunnel->dev->stats.rx_fifo_errors++;
				tunnel->dev->stats.rx_errors++;
				goto drop;
			}
			tunnel->i_seqno = seqno + 1;
		}
		tunnel->dev->stats.rx_packets++;
		tunnel->dev->stats.rx_bytes += skb->len;
		skb->dev = tunnel->dev;
		dst_release(skb->dst);
		skb->dst = NULL;
		nf_reset(skb);
		ipgre_ecn_decapsulate(iph, skb);
		netif_rx(skb);
		read_unlock(&ipgre_lock);
		return(0);
	}
	icmp_send(skb, ICMP_DEST_UNREACH, ICMP_PORT_UNREACH, 0);

drop:
	read_unlock(&ipgre_lock);
drop_nolock:
	kfree_skb(skb);
	return(0);
}

static int ipgre_ip_tunnel_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct ip_tunnel *tunnel = netdev_priv(dev);
	struct net_device_stats *stats = &tunnel->dev->stats;
	struct iphdr  *old_iph = ip_hdr(skb);
	struct iphdr  *tiph;
	u8     tos;
	__be16 df;
	struct rtable *rt;     			/* Route to the other host */
	struct net_device *tdev;			/* Device to other host */
	struct iphdr  *iph;			/* Our new IP header */
	int    max_headroom;			/* The extra header space needed */
	int    gre_hlen;
	__be32 dst;
	int    mtu;

	if (tunnel->recursion++) {
		tunnel->dev->stats.collisions++;
		goto tx_error;
	}

	if (dev->header_ops) {
		gre_hlen = 0;
		tiph = (struct iphdr*)skb->data;
	} else {
		gre_hlen = tunnel->hlen;
		tiph = &tunnel->parms.iph;
	}

	if ((dst = tiph->daddr) == 0) {
		/* NBMA tunnel */

		if (skb->dst == NULL) {
			tunnel->dev->stats.tx_fifo_errors++;
			goto tx_error;
		}

		if (skb->protocol == htons(ETH_P_IP)) {
			rt = (struct rtable*)skb->dst;
			if ((dst = rt->rt_gateway) == 0)
				goto tx_error_icmp;
		}
#ifdef CONFIG_IPV6
		else if (skb->protocol == htons(ETH_P_IPV6)) {
			struct in6_addr *addr6;
			int addr_type;
			struct neighbour *neigh = skb->dst->neighbour;

			if (neigh == NULL)
				goto tx_error;

			addr6 = (struct in6_addr*)&neigh->primary_key;
			addr_type = ipv6_addr_type(addr6);

			if (addr_type == IPV6_ADDR_ANY) {
				addr6 = &ipv6_hdr(skb)->daddr;
				addr_type = ipv6_addr_type(addr6);
			}

			if ((addr_type & IPV6_ADDR_COMPATv4) == 0)
				goto tx_error_icmp;

		}
#endif
		else
			goto tx_error;
	}

	tos = tiph->tos;
	if (tos&1) {
		if (skb->protocol == htons(ETH_P_IP))
			tos = old_iph->tos;
		tos &= ~1;
	}

	{
		struct flowi fl = { //.fl_net = &init_net,
				    .oif = tunnel->parms.link,
				    .nl_u = { .ip4_u =
					      { .daddr = dst,
						.saddr = tiph->saddr,
						.tos = RT_TOS(tos) } },
				    .proto = IPPROTO_GRE };
		if (ip_route_output_key(dev_net(dev),&rt, &fl)) {
			tunnel->dev->stats.tx_carrier_errors++;
			goto tx_error;
		}
	}
	tdev = rt->u.dst.dev;


	if (tdev == dev) {
		ip_rt_put(rt);
		tunnel->dev->stats.collisions++;
		goto tx_error;
	}

	df = tiph->frag_off;
	if (df)
		mtu = dst_mtu(&rt->u.dst) - tunnel->hlen;
	else
		mtu = skb->dst ? dst_mtu(skb->dst) : dev->mtu;

	if (skb->dst)
		skb->dst->ops->update_pmtu(skb->dst, mtu);

	if (skb->protocol == htons(ETH_P_IP)) {
		df |= (old_iph->frag_off&htons(IP_DF));

		if ((old_iph->frag_off&htons(IP_DF)) &&
		    mtu < ntohs(old_iph->tot_len)) {
			icmp_send(skb, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED, htonl(mtu));
			ip_rt_put(rt);
			goto tx_error;
		}
	}
#ifdef CONFIG_IPV6
	else if (skb->protocol == htons(ETH_P_IPV6)) {
		struct rt6_info *rt6 = (struct rt6_info*)skb->dst;

		if (rt6 && mtu < dst_mtu(skb->dst) && mtu >= IPV6_MIN_MTU) {
			if ((tunnel->parms.iph.daddr && !ipv4_is_multicast(tunnel->parms.iph.daddr)) ||
			    rt6->rt6i_dst.plen == 128) {
				rt6->rt6i_flags |= RTF_MODIFIED;
				skb->dst->metrics[RTAX_MTU-1] = mtu;
			}
		}

		if (mtu >= IPV6_MIN_MTU && mtu < skb->len - tunnel->hlen + gre_hlen) {
			icmpv6_send(skb, ICMPV6_PKT_TOOBIG, 0, mtu, dev);
			ip_rt_put(rt);
			goto tx_error;
		}
	}
#endif

	if (tunnel->err_count > 0) {
		if (jiffies - tunnel->err_time < IPTUNNEL_ERR_TIMEO) {
			tunnel->err_count--;

			dst_link_failure(skb);
		} else
			tunnel->err_count = 0;
	}

	max_headroom = LL_RESERVED_SPACE(tdev) + gre_hlen;

	if (skb_headroom(skb) < max_headroom || skb_cloned(skb) || skb_shared(skb)) {
		struct sk_buff *new_skb = skb_realloc_headroom(skb, max_headroom);
		if (!new_skb) {
			ip_rt_put(rt);
			stats->tx_dropped++;
			dev_kfree_skb(skb);
			tunnel->recursion--;
			return 0;
		}
		if (skb->sk)
			skb_set_owner_w(new_skb, skb->sk);
		dev_kfree_skb(skb);
		skb = new_skb;
		old_iph = ip_hdr(skb);
	}

	skb->transport_header = skb->network_header;
	skb_push(skb, gre_hlen);
	memset(&(IPCB(skb)->opt), 0, sizeof(IPCB(skb)->opt));
	IPCB(skb)->flags &= ~(IPSKB_XFRM_TUNNEL_SIZE | IPSKB_XFRM_TRANSFORMED |
			      IPSKB_REROUTED);
	dst_release(skb->dst);
	skb->dst = &rt->u.dst;

	/*
	 *	Push down and install the IPIP header.
	 */

	iph 			=	ip_hdr(skb);
	iph->version		=	4;
	iph->ihl		=	sizeof(struct iphdr) >> 2;
	iph->frag_off		=	df;
	iph->protocol		=	IPPROTO_GRE;
	iph->tos		=	ipgre_ecn_encapsulate(tos, old_iph, skb);
	iph->daddr		=	rt->rt_dst;
	iph->saddr		=	rt->rt_src;

	if ((iph->ttl = tiph->ttl) == 0) {
		if (skb->protocol == htons(ETH_P_IP))
			iph->ttl = old_iph->ttl;
#ifdef CONFIG_IPV6
		else if (skb->protocol == htons(ETH_P_IPV6))
			iph->ttl = ((struct ipv6hdr*)old_iph)->hop_limit;
#endif
		else
			iph->ttl = dst_metric(&rt->u.dst, RTAX_HOPLIMIT);
	}

	((__be16*)(iph+1))[0] = tunnel->parms.o_flags;
	((__be16*)(iph+1))[1] = skb->protocol;

	if (tunnel->parms.o_flags&(GRE_KEY|GRE_CSUM|GRE_SEQ)) {
		__be32 *ptr = (__be32*)(((u8*)iph) + tunnel->hlen - 4);

		if (tunnel->parms.o_flags&GRE_SEQ) {
			++tunnel->o_seqno;
			*ptr = htonl(tunnel->o_seqno);
			ptr--;
		}
		if (tunnel->parms.o_flags&GRE_KEY) {
			*ptr = tunnel->parms.o_key;
			ptr--;
		}
		if (tunnel->parms.o_flags&GRE_CSUM) {
			*ptr = 0;
			*(__sum16*)ptr = ip_compute_csum((void*)(iph+1), skb->len - sizeof(struct iphdr));
		}
	}

	nf_reset(skb);

	IPTUNNEL_XMIT();
	tunnel->recursion--;
	return 0;

tx_error_icmp:
	dst_link_failure(skb);

tx_error:
	stats->tx_errors++;
	dev_kfree_skb(skb);
	tunnel->recursion--;
	return 0;
}

static int ipgre_eth_tunnel_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct ip_tunnel *tunnel = netdev_priv(dev);
	struct net_device_stats *stats = &tunnel->dev->stats;
	struct iphdr *old_iph = ip_hdr(skb);
	struct iphdr *tiph = &tunnel->parms.iph;
	u8     tos;
	__be16 df;
	struct rtable *rt;     		/* Route to the other host */
	struct net_device *tdev;	/* Device to other host */
	int    gre_hlen = tunnel->hlen; /* XXX changed XXX*/
	//struct etheriphdr  *ethiph;
	struct iphdr  *iph;		/* Our new IP header */
	int    max_headroom;		/* The extra header space needed */
	int    mtu;

#ifdef GRE_DEBUG
	printk(KERN_ALERT "gre.c:972 Starting xmit\n");
#endif

	if (tunnel->recursion++) {
		stats->collisions++;
		goto tx_error;
	}

	/* Need valid non-ipv4_is_multicast daddr.  */
	if (tiph->daddr == 0 || ipv4_is_multicast(tiph->daddr))
		goto tx_error;

	tos = tiph->tos;
	if (tos&1) {
		if (skb->protocol == htons(ETH_P_IP))
			tos = old_iph->tos;
		tos &= ~1;
	}
#ifdef GRE_DEBUG
	printk(KERN_ALERT "gre.c:991 Passed tos assignment.\n");
#endif


	{
		struct flowi fl = { //.fl_net = &init_net,
		    		    .oif = tunnel->parms.link,
				    .nl_u = { .ip4_u =
					      { .daddr = tiph->daddr,
						.saddr = tiph->saddr,
						.tos = RT_TOS(tos) } },
				    .proto = IPPROTO_GRE };
		if (ip_route_output_key(dev_net(dev),&rt, &fl)) {
			stats->tx_carrier_errors++;
			goto tx_error_icmp;
		}
	}
	tdev = rt->u.dst.dev;
#ifdef GRE_DEBUG
	printk(KERN_ALERT "gre.c:1006 Passed the route retrieval\n");
#endif
	if (tdev == dev) {
		ip_rt_put(rt);
		stats->collisions++;
		goto tx_error;
	}
#ifdef GRE_DEBUG
	printk(KERN_ALERT "gre.c:1018 Passed tdev collision check.\n");
#endif

	/* Check MTU stuff if kernel panic */
	df = tiph->frag_off;
	if (df)
		mtu = dst_mtu(&rt->u.dst) - tunnel->hlen;
	else
		mtu = skb->dst ? dst_mtu(skb->dst) : dev->mtu;
/*
	if (skb->dst)
		skb->dst->ops->update_pmtu(skb->dst, mtu);
	 XXX */
#ifdef GRE_DEBUG
	printk(KERN_ALERT "gre.c:1032 Passed the pmtu setting.\n");
#endif

	if (skb->protocol == htons(ETH_P_IP)) {
		df |= (old_iph->frag_off&htons(IP_DF));

		if ((old_iph->frag_off & htons(IP_DF)) &&
		    mtu < ntohs(old_iph->tot_len)) {
			icmp_send(skb, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED, htonl(mtu));
			ip_rt_put(rt);
			goto tx_error;
		}
	}
#ifdef CONFIG_IPV6
	else if (skb->protocol == htons(ETH_P_IPV6)) {
		struct rt6_info *rt6 = (struct rt6_info*)skb->dst;

		if (rt6 && mtu < dst_mtu(skb->dst) && mtu >= IPV6_MIN_MTU) {
			if (tiph->daddr || rt6->rt6i_dst.plen == 128) {
				rt6->rt6i_flags |= RTF_MODIFIED;
				skb->dst->metrics[RTAX_MTU-1] = mtu;
			}
		}

		/* @@@ Is this correct?  */
		if (mtu >= IPV6_MIN_MTU && mtu < skb->len - tunnel->hlen + gre_hlen) {
			icmpv6_send(skb, ICMPV6_PKT_TOOBIG, 0, mtu, dev);
			ip_rt_put(rt);
			goto tx_error;
		}
	}
#endif
#ifdef GRE_DEBUG
	printk(KERN_ALERT "gre.c:1065 Passed the fragmentation check.\n");
#endif

	if (tunnel->err_count > 0) {
		if (jiffies - tunnel->err_time < IPTUNNEL_ERR_TIMEO) {
			tunnel->err_count--;
			dst_link_failure(skb);
		} else
			tunnel->err_count = 0;
	}

	max_headroom = LL_RESERVED_SPACE(tdev) + gre_hlen;

	if (skb_headroom(skb) < max_headroom || skb_cloned(skb) || skb_shared(skb)) {
		struct sk_buff *new_skb = skb_realloc_headroom(skb, max_headroom);
		if (!new_skb) {
			ip_rt_put(rt);
  			stats->tx_dropped++;
			dev_kfree_skb(skb);
			tunnel->recursion--;
			return 0;
		}
		if (skb->sk)
			skb_set_owner_w(new_skb, skb->sk);
		dev_kfree_skb(skb);
		skb = new_skb;
		old_iph = ip_hdr(skb);
	}
#ifdef GRE_DEBUG
	printk(KERN_ALERT "gre.c:1094 Passed the headroom calculation\n");
#endif


	skb->transport_header = skb->mac_header; // Added by valas
	skb_push(skb, gre_hlen);
	skb_reset_network_header(skb);
	memset(&(IPCB(skb)->opt), 0, sizeof(IPCB(skb)->opt));
	dst_release(skb->dst);
	skb->dst = &rt->u.dst;

	/*
	 *	Push down and install the etherip header.
	 */

	iph			=	ip_hdr(skb);
	iph->version		=	4;
	iph->ihl		=	sizeof(struct iphdr) >> 2;
	iph->frag_off		=	df;
	iph->protocol		=	IPPROTO_GRE;
	iph->tos		=	ipgre_ecn_encapsulate(tos, old_iph, skb);
	iph->daddr		=	rt->rt_dst;
	iph->saddr		=	rt->rt_src;

/* 	ethiph->version		=	htons(ETHERIP_VERSION); */
#ifdef GRE_DEBUG
	printk(KERN_ALERT "gre.c:1121 Passed outer IP header construction.\n");
#endif

	if ((iph->ttl = tiph->ttl) == 0) {
		if (skb->protocol == htons(ETH_P_IP))
			iph->ttl = old_iph->ttl;
#ifdef CONFIG_IPV6
		else if (skb->protocol == htons(ETH_P_IPV6))
			iph->ttl = ((struct ipv6hdr*)old_iph)->hop_limit;
#endif
		else
			iph->ttl = dst_metric(&rt->u.dst, RTAX_HOPLIMIT);
	}
#ifdef GRE_DEBUG
	printk(KERN_ALERT "gre.c:1006 Passed the TTL check.\n");
#endif

	((__be16*)(iph+1))[0] = tunnel->parms.o_flags;
	((__be16*)(iph+1))[1] = htons(tunnel->parms.proto_type);

	if (tunnel->parms.o_flags&(GRE_KEY|GRE_CSUM|GRE_SEQ)) {
		__be32 *ptr = (__be32*)(((u8*)iph) + tunnel->hlen - 4);

		if (tunnel->parms.o_flags&GRE_SEQ) {
			++tunnel->o_seqno;
			*ptr = htonl(tunnel->o_seqno);
			ptr--;
		}
		if (tunnel->parms.o_flags&GRE_KEY) {
			*ptr = tunnel->parms.o_key;
			ptr--;
		}
		if (tunnel->parms.o_flags&GRE_CSUM) {
			*ptr = 0;
			*(__sum16*)ptr = ip_compute_csum((void*)(iph+1), skb->len - sizeof(struct iphdr));
		}
	}
#ifdef GRE_DEBUG
	printk(KERN_ALERT "gre.c:1006 Passed the tunnel transmit.\n");
#endif

	nf_reset(skb);

	IPTUNNEL_XMIT();
	tunnel->recursion--;
	return 0;

tx_error_icmp:
	dst_link_failure(skb);

tx_error:
	stats->tx_errors++;
	dev_kfree_skb(skb);
	tunnel->recursion--;
	return 0;
}


static int
ipgre_tunnel_ioctl (struct net_device *dev, struct ifreq *ifr, int cmd)
{
	int err = 0;
	struct ip_tunnel_parm p;
	struct ip_tunnel *t;

        printk(KERN_ALERT "1174 GRE: entering gre ioctl. command is: %d\n", cmd);

	switch (cmd) {
	case SIOCGETTUNNEL:
		t = NULL;
		if (dev == ipgre_fb_tunnel_dev) {
			if (copy_from_user(&p, ifr->ifr_ifru.ifru_data, sizeof(p))) {
				err = -EFAULT;
				break;
			}
			t = ipgre_tunnel_locate(&p, 0);
		}
		if (t == NULL)
			t = netdev_priv(dev);
		memcpy(&p, &t->parms, sizeof(p));
		if (copy_to_user(ifr->ifr_ifru.ifru_data, &p, sizeof(p)))
			err = -EFAULT;
		break;

	case SIOCADDTUNNEL:
	case SIOCCHGTUNNEL:
		err = -EPERM;
		if (!capable(CAP_NET_ADMIN))
			goto done;

		err = -EFAULT;
		if (copy_from_user(&p, ifr->ifr_ifru.ifru_data, sizeof(p)))
			goto done;

		err = -EINVAL;
		if (p.iph.version != 4 || p.iph.protocol != IPPROTO_GRE ||
		    p.iph.ihl != 5 || (p.iph.frag_off&htons(~IP_DF)) ||
		    ((p.i_flags|p.o_flags)&(GRE_VERSION|GRE_ROUTING)))
			goto done;
		if (p.iph.ttl)
			p.iph.frag_off |= htons(IP_DF);

		if (!(p.i_flags&GRE_KEY))
			p.i_key = 0;
		if (!(p.o_flags&GRE_KEY))
			p.o_key = 0;

		t = ipgre_tunnel_locate(&p, cmd == SIOCADDTUNNEL);
		if (t) printk(KERN_ALERT "1174 GRE: proto %s %d\n", p.name, p.proto_type);
		if (dev != ipgre_fb_tunnel_dev && cmd == SIOCCHGTUNNEL) {
			if (t != NULL) {
				if (t->dev != dev) {
					err = -EEXIST;
					break;
				}
			} else {
				unsigned nflags=0;

				t = netdev_priv(dev);

				if (ipv4_is_multicast(p.iph.daddr))
					nflags = IFF_BROADCAST;
				else if (p.iph.daddr)
					nflags = IFF_POINTOPOINT;
				
				/* XXX:Set back IFF_BROADCAST if
				 * transporting ethernet */
				printk(KERN_ALERT "1193 GRE: proto %s %d\n", p.name, p.proto_type);
				if (p.proto_type == ETH_P_ETH)
				    	nflags = IFF_BROADCAST;

				if ((dev->flags^nflags)&(IFF_POINTOPOINT|IFF_BROADCAST)) {
					err = -EINVAL;
					break;
				}
				ipgre_tunnel_unlink(t);
				t->parms.iph.saddr = p.iph.saddr;
				t->parms.iph.daddr = p.iph.daddr;
				t->parms.i_key = p.i_key;
				t->parms.o_key = p.o_key;
				/* XXX:Copy in the protocol field */
				t->parms.proto_type = p.proto_type;
				if (t->parms.proto_type != ETH_P_ETH)
				{
					memcpy(dev->dev_addr, &p.iph.saddr, 4);
					memcpy(dev->broadcast, &p.iph.daddr, 4);
				}
				ipgre_tunnel_link(t);
				netdev_state_change(dev);
			}
		}

		if (t) {
			err = 0;
			if (cmd == SIOCCHGTUNNEL) {
				t->parms.iph.ttl = p.iph.ttl;
				t->parms.iph.tos = p.iph.tos;
				t->parms.iph.frag_off = p.iph.frag_off;
			}
			if (copy_to_user(ifr->ifr_ifru.ifru_data, &t->parms, sizeof(p)))
				err = -EFAULT;
		} else
			err = (cmd == SIOCADDTUNNEL ? -ENOBUFS : -ENOENT);
		break;

	case SIOCDELTUNNEL:
		err = -EPERM;
		if (!capable(CAP_NET_ADMIN))
			goto done;

		if (dev == ipgre_fb_tunnel_dev) {
			err = -EFAULT;
			if (copy_from_user(&p, ifr->ifr_ifru.ifru_data, sizeof(p)))
				goto done;
			err = -ENOENT;
			if ((t = ipgre_tunnel_locate(&p, 0)) == NULL)
				goto done;
			err = -EPERM;
			if (t == netdev_priv(ipgre_fb_tunnel_dev))
				goto done;
			dev = t->dev;
		}
		unregister_netdevice(dev); // added by Valas
		break;

	default:
		err = -EINVAL;
	}

done:
	return err;
}

static struct net_device_stats *ipgre_tunnel_get_stats(struct net_device *dev)
{
	return &(((struct ip_tunnel*)netdev_priv(dev))->dev->stats);
}

static int ipgre_tunnel_change_mtu(struct net_device *dev, int new_mtu)
{
	struct ip_tunnel *tunnel = netdev_priv(dev);
	if (new_mtu < 68 || new_mtu > 0xFFF8 - tunnel->hlen)
		return -EINVAL;
	dev->mtu = new_mtu;
	return 0;
}

#ifdef CONFIG_NET_IPGRE_BROADCAST
/* Nice toy. Unfortunately, useless in real life :-)
   It allows to construct virtual multiprotocol broadcast "LAN"
   over the Internet, provided ipv4_is_multicast routing is tuned.


   I have no idea was this bicycle invented before me,
   so that I had to set ARPHRD_IPGRE to a random value.
   I have an impression, that Cisco could make something similar,
   but this feature is apparently missing in IOS<=11.2(8).

   I set up 10.66.66/24 and fec0:6666:6666::0/96 as virtual networks
   with broadcast 224.66.66.66. If you have access to mbone, play with me :-)

   ping -t 255 224.66.66.66

   If nobody answers, mbone does not work.

   ip tunnel add Universe mode gre remote 224.66.66.66 local <Your_real_addr> ttl 255
   ip addr add 10.66.66.<somewhat>/24 dev Universe
   ifconfig Universe up
   ifconfig Universe add fe80::<Your_real_addr>/10
   ifconfig Universe add fec0:6666:6666::<Your_real_addr>/96
   ftp 10.66.66.66
   ...
   ftp fec0:6666:6666::193.233.7.65
   ...

 */

static int ipgre_open(struct net_device *dev)
{
	struct ip_tunnel *t = netdev_priv(dev);

	if (ipv4_is_multicast(t->parms.iph.daddr)) {
		struct flowi fl = { //.fl_net = &init_net,
				    .oif = t->parms.link,
				    .nl_u = { .ip4_u =
					      { .daddr = t->parms.iph.daddr,
						.saddr = t->parms.iph.saddr,
						.tos = RT_TOS(t->parms.iph.tos) } },
				    .proto = IPPROTO_GRE };
		struct rtable *rt;
		if (ip_route_output_key(dev_net(dev),&rt, &fl))
			return -EADDRNOTAVAIL;
		dev = rt->u.dst.dev;
		ip_rt_put(rt);
		if (__in_dev_get_rtnl(dev) == NULL)
			return -EADDRNOTAVAIL;
		t->mlink = dev->ifindex;
		ip_mc_inc_group(__in_dev_get_rtnl(dev), t->parms.iph.daddr);
	}
	return 0;
}

static int ipgre_close(struct net_device *dev)
{
	struct ip_tunnel *t = netdev_priv(dev);
	if (ipv4_is_multicast(t->parms.iph.daddr) && t->mlink) {
		struct in_device *in_dev = inetdev_by_index(&init_net, t->mlink);
		if (in_dev) {
			ip_mc_dec_group(in_dev, t->parms.iph.daddr);
			in_dev_put(in_dev);
		}
	}
	return 0;
}

#endif

static void ipgre_ip_tunnel_setup(struct net_device *dev)
{
	//SET_MODULE_OWNER(dev);
	dev->uninit		= ipgre_tunnel_uninit;
	dev->destructor 	= free_netdev;
	dev->hard_start_xmit	= ipgre_ip_tunnel_xmit;
	dev->get_stats		= ipgre_tunnel_get_stats;
	dev->do_ioctl		= ipgre_tunnel_ioctl;
	dev->change_mtu		= ipgre_tunnel_change_mtu;

	dev->type		= ARPHRD_IPGRE;
	dev->hard_header_len 	= LL_MAX_HEADER + sizeof(struct iphdr) + 4;
	dev->mtu		= ETH_DATA_LEN - sizeof(struct iphdr) - 4;
	dev->flags		= IFF_NOARP;
	dev->iflink		= 0;
	dev->addr_len		= 4;
}

/* Tunnel setup for ipgre_eth */
static void ipgre_eth_tunnel_setup(struct net_device *dev)
{
	//SET_MODULE_OWNER(dev);
	ether_setup(dev);

	dev->uninit		= ipgre_tunnel_uninit;
	dev->destructor 	= free_netdev;
	dev->hard_start_xmit	= ipgre_eth_tunnel_xmit;
	dev->get_stats		= ipgre_tunnel_get_stats;
	dev->do_ioctl		= ipgre_tunnel_ioctl;
	dev->change_mtu		= ipgre_tunnel_change_mtu;

	dev->hard_header_len	= ETH_HLEN + sizeof(struct iphdr) + 4;
	dev->tx_queue_len	= 0;
	random_ether_addr(dev->dev_addr);

#ifdef GRE_DEBUG
	unsigned char* d = dev->dev_addr;
	printk(KERN_ALERT "Here is the address we got:%x%x%x%x%x%x\n",d[0],d[1],d[2],d[3],d[4],d[5]);
#endif	

	dev->iflink		= 0;
}

static int ipgre_header(struct sk_buff *skb, struct net_device *dev,
            unsigned short type,
            const void *daddr, const void *saddr, unsigned len)
{
    struct ip_tunnel *t = netdev_priv(dev);
    struct iphdr *iph = (struct iphdr *)skb_push(skb, t->hlen);
    __be16 *p = (__be16*)(iph+1);

    memcpy(iph, &t->parms.iph, sizeof(struct iphdr));
    p[0]        = t->parms.o_flags;
    p[1]        = htons(type);

    /*
     *  Set the source hardware address.
     */

    if (saddr)
        memcpy(&iph->saddr, saddr, 4);

    if (daddr) {
        memcpy(&iph->daddr, daddr, 4);
        return t->hlen;
    }
    if (iph->daddr && !ipv4_is_multicast(iph->daddr))
        return t->hlen;

    return -t->hlen;
}

static int ipgre_header_parse(const struct sk_buff *skb, unsigned char *haddr)
{
    struct iphdr *iph = (struct iphdr*) skb_mac_header(skb);
    memcpy(haddr, &iph->saddr, 4);
    return 4;
}

static const struct header_ops ipgre_header_ops = {
    .create = ipgre_header,
    .parse  = ipgre_header_parse,
};

static int ipgre_tunnel_init(struct net_device *dev)
{
	struct net_device *tdev = NULL;
	struct ip_tunnel *tunnel;
	struct iphdr *iph;
	int hlen = LL_MAX_HEADER;
	int mtu = ETH_DATA_LEN;
	int addend = sizeof(struct iphdr) + 4;

	tunnel = netdev_priv(dev);
	iph = &tunnel->parms.iph;

	tunnel->dev = dev;
	strcpy(tunnel->parms.name, dev->name);

	if (tunnel->parms.proto_type != ETH_P_ETH)
	{
		memcpy(dev->dev_addr, &tunnel->parms.iph.saddr, 4);
		memcpy(dev->broadcast, &tunnel->parms.iph.daddr, 4);
	}

	/* Guess output device to choose reasonable mtu and hard_header_len */

	if (iph->daddr) {
		struct flowi fl = { //.fl_net = &init_net,
				    .oif = tunnel->parms.link,
				    .nl_u = { .ip4_u =
					      { .daddr = iph->daddr,
						.saddr = iph->saddr,
						.tos = RT_TOS(iph->tos) } },
				    .proto = IPPROTO_GRE };
		struct rtable *rt;
		if (!ip_route_output_key(dev_net(dev), &rt, &fl)) {
			tdev = rt->u.dst.dev;
			ip_rt_put(rt);
		}

		if (tunnel->parms.proto_type == ETH_P_ETH)
		{
		    dev->flags |= IFF_BROADCAST;
		}
		else
		{
			dev->flags |= IFF_POINTOPOINT;
		}

#ifdef CONFIG_NET_IPGRE_BROADCAST
		if (ipv4_is_multicast(iph->daddr)) {
			if (!iph->saddr)
				return -EINVAL;
			dev->flags = IFF_BROADCAST;
			dev->header_ops = &ipgre_header_ops;
			dev->open = ipgre_open;
			dev->stop = ipgre_close;
		}
#endif
	}

	if (!tdev && tunnel->parms.link)
		tdev = __dev_get_by_index(&init_net, tunnel->parms.link);

	if (tdev) {
		hlen = tdev->hard_header_len;
		mtu = tdev->mtu;
	}
	dev->iflink = tunnel->parms.link;

	/* Precalculate GRE options length */
	if (tunnel->parms.o_flags&(GRE_CSUM|GRE_KEY|GRE_SEQ)) {
		if (tunnel->parms.o_flags&GRE_CSUM)
			addend += 4;
		if (tunnel->parms.o_flags&GRE_KEY)
			addend += 4;
		if (tunnel->parms.o_flags&GRE_SEQ)
			addend += 4;
	}
	dev->hard_header_len = hlen + addend;
	dev->mtu = mtu - addend;
	tunnel->hlen = addend;
	return 0;
}

static int __init ipgre_fb_tunnel_init(struct net_device *dev)
{
	struct ip_tunnel *tunnel = netdev_priv(dev);
	struct iphdr *iph = &tunnel->parms.iph;

	tunnel->dev = dev;
	strcpy(tunnel->parms.name, dev->name);

	iph->version		= 4;
	iph->protocol		= IPPROTO_GRE;
	iph->ihl		= 5;
	tunnel->hlen		= sizeof(struct iphdr) + 4;

	dev_hold(dev);
	tunnels_wc[0]		= tunnel;
	return 0;
}


static struct net_protocol ipgre_protocol = {
	.handler	=	ipgre_rcv,
	.err_handler	=	ipgre_err,
};


/*
 *	And now the modules code and kernel interface.
 */

static int __init ipgre_init(void)
{
	int err;

	printk(KERN_INFO "GRE over IPv4 tunneling driver\n");

	if (inet_add_protocol(&ipgre_protocol, IPPROTO_GRE) < 0) {
		printk(KERN_INFO "ipgre init: can't add protocol\n");
		return -EAGAIN;
	}

	ipgre_fb_tunnel_dev = alloc_netdev(sizeof(struct ip_tunnel), "gre0",
					   ipgre_ip_tunnel_setup);
	if (!ipgre_fb_tunnel_dev) {
		err = -ENOMEM;
		goto err1;
	}

	ipgre_fb_tunnel_dev->init = ipgre_fb_tunnel_init;

	if ((err = register_netdev(ipgre_fb_tunnel_dev)))
		goto err2;
out:
	return err;
err2:
	free_netdev(ipgre_fb_tunnel_dev);
err1:
	inet_del_protocol(&ipgre_protocol, IPPROTO_GRE);
	goto out;
}

static void __exit ipgre_destroy_tunnels(void)
{
	int prio;

	for (prio = 0; prio < 4; prio++) {
		int h;
		for (h = 0; h < HASH_SIZE; h++) {
			struct ip_tunnel *t;
			while ((t = tunnels[prio][h]) != NULL)
				unregister_netdevice(t->dev);
		}
	}
}

static void __exit ipgre_fini(void)
{
	if (inet_del_protocol(&ipgre_protocol, IPPROTO_GRE) < 0)
		printk(KERN_INFO "ipgre close: can't remove protocol\n");

	rtnl_lock();
	ipgre_destroy_tunnels();
	rtnl_unlock();
}

module_init(ipgre_init);
module_exit(ipgre_fini);
MODULE_LICENSE("GPL");
