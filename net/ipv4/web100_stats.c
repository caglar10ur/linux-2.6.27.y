/*	
 * net/ipv4/web100_stats.c
 *
 * Copyright (C) 2001 Matt Mathis <mathis@psc.edu>
 * Copyright (C) 2001 John Heffner <jheffner@psc.edu>
 * Copyright (C) 2000 Jeffrey Semke <semke@psc.edu>
 *
 * The Web 100 project.  See http://www.web100.org
 *
 *	Functions for creating, destroying, and updating the Web100
 *	statistics structure.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <linux/types.h>
#include <linux/socket.h>
#include <net/web100.h>
#include <net/tcp.h>
#include <linux/string.h>
#include <linux/proc_fs.h>
#include <asm/atomic.h>

#define WC_INF32	0xffffffff

#define WC_DEATH_SLOTS	8
#define WC_PERSIST_TIME	60

/* BEWARE: The release process updates the version string */
char *web100_version_string = "2.5.17 200710051837"
#ifdef CONFIG_WEB100_NET100
    " net100"
#endif
    ;

static void death_cleanup(unsigned long dummy);

/* Global stats reader-writer lock */
rwlock_t web100_linkage_lock = RW_LOCK_UNLOCKED;

/* Data structures for tying together stats */
static int web100stats_next_cid;
static int web100stats_conn_num;
static int web100stats_htsize;
struct web100stats **web100stats_ht;
struct web100stats *web100stats_first = NULL;

static struct web100stats *death_slots[WC_DEATH_SLOTS];
static int cur_death_slot;
static spinlock_t death_lock = SPIN_LOCK_UNLOCKED;
static struct timer_list stats_persist_timer = TIMER_INITIALIZER(death_cleanup, 0, 0);
static int ndeaths;

#ifdef CONFIG_WEB100_NETLINK
static struct sock *web100_nlsock;
#endif

extern struct proc_dir_entry *proc_web100_dir;


/*
 * Structural maintainance
 */

static inline int web100stats_hash(int cid)
{
	return cid % web100stats_htsize;
}

struct web100stats *web100stats_lookup(int cid)
{
	struct web100stats *stats;
	
	/* Let's ensure safety here.  It's not too expensive and may change. */
	if (cid < 0 || cid >= WEB100_MAX_CONNS)
		return NULL;
	
	stats = web100stats_ht[web100stats_hash(cid)];
	while (stats && stats->wc_cid != cid)
		stats = stats->wc_hash_next;
	return stats;
}

/* This will get really slow as the cid space fills.  This can be done
 * better, but it's just not worth it right now.
 * The caller must hold the lock.
 */
static int get_next_cid(void)
{
	int i;
	
	if (web100stats_conn_num >= WEB100_MAX_CONNS)
		return -1;
	
	i = web100stats_next_cid;
	do {
		if (web100stats_lookup(i) == NULL)
			break;
		i = (i + 1) % WEB100_MAX_CONNS;
	} while (i != web100stats_next_cid);
	web100stats_next_cid = (i + 1) % WEB100_MAX_CONNS;
	
	return i;
}

static void stats_link(struct web100stats *stats)
{
	int hash;
	
	write_lock_bh(&web100_linkage_lock);
	
	if ((stats->wc_cid = get_next_cid()) < 0) {
		write_unlock_bh(&web100_linkage_lock);
		return;
	}
	
	hash = web100stats_hash(stats->wc_cid);
	stats->wc_hash_next = web100stats_ht[hash];
	stats->wc_hash_prev = NULL;
	if (web100stats_ht[hash])
		web100stats_ht[hash]->wc_hash_prev = stats;
	web100stats_ht[hash] = stats;
	
	stats->wc_next = web100stats_first;
	stats->wc_prev = NULL;
	if (web100stats_first)
		web100stats_first->wc_prev = stats;
	web100stats_first = stats;
	
	web100stats_conn_num++;
	proc_web100_dir->nlink = web100stats_conn_num + 2;
	
	write_unlock_bh(&web100_linkage_lock);
}

static void stats_unlink(struct web100stats *stats)
{
	int hash;
	
	write_lock_bh(&web100_linkage_lock);
	
	hash = web100stats_hash(stats->wc_cid);
	if (stats->wc_hash_next)
		stats->wc_hash_next->wc_hash_prev = stats->wc_hash_prev;
	if (stats->wc_hash_prev)
		stats->wc_hash_prev->wc_hash_next = stats->wc_hash_next;
	if (stats == web100stats_ht[hash])
		web100stats_ht[hash] = stats->wc_hash_next ?
					stats->wc_hash_next :
					stats->wc_hash_prev;
	
	if (stats->wc_next)
		stats->wc_next->wc_prev = stats->wc_prev;
	if (stats->wc_prev)
		stats->wc_prev->wc_next = stats->wc_next;
	if (stats == web100stats_first)
		web100stats_first = stats->wc_next ? stats->wc_next :
						      stats->wc_prev;
	
	web100stats_conn_num--;
	proc_web100_dir->nlink = web100stats_conn_num + 2;
	
	write_unlock_bh(&web100_linkage_lock);
}

static void stats_persist(struct web100stats *stats)
{
	spin_lock_bh(&death_lock);
	
	stats->wc_death_next = death_slots[cur_death_slot];
	death_slots[cur_death_slot] = stats;
	if (ndeaths <= 0) {
		stats_persist_timer.expires = jiffies + WC_PERSIST_TIME * HZ / WC_DEATH_SLOTS;
		add_timer(&stats_persist_timer);
	}
	ndeaths++;
	
	spin_unlock_bh(&death_lock);
}

static void death_cleanup(unsigned long dummy)
{
	struct web100stats *stats, *next;
	
	spin_lock_bh(&death_lock);
	
	cur_death_slot = (cur_death_slot + 1) % WC_DEATH_SLOTS;
	stats = death_slots[cur_death_slot];
	while (stats) {
		stats->wc_dead = 1;
		ndeaths--;
		next = stats->wc_death_next;
		web100_stats_unuse(stats);
		stats = next;
	}
	death_slots[cur_death_slot] = NULL;

	if (ndeaths > 0) {
		stats_persist_timer.expires = jiffies + WC_PERSIST_TIME * HZ / WC_DEATH_SLOTS;
		add_timer(&stats_persist_timer);
	}
	
	spin_unlock_bh(&death_lock);
}


/* Tom Dunigan's (slightly modified) netlink code.  Notifies listening apps
 * of Web100 events.
 *
 * NOTE: we are currently squatting on netlink family 10 (NETLINK_WEB100) in
 * include/linux/netlink.h
 */

#ifdef CONFIG_WEB100_NETLINK
void web100_netlink_event(int type, int cid)
{
	struct web100_netlink_msg *msg;
	struct sk_buff *tmpskb;
	
	if (web100_nlsock == NULL)
		return;
	
	if ((tmpskb = alloc_skb((sizeof (struct web100_netlink_msg)), GFP_ATOMIC)) == NULL) {
		printk(KERN_INFO "web100_netlink_event: alloc_skb failure\n");
		return;
	}
	
	skb_put(tmpskb, sizeof (struct web100_netlink_msg));
	msg = (struct web100_netlink_msg *)tmpskb->data;
	msg->type = type;
	msg->cid = cid;
	netlink_broadcast(web100_nlsock, tmpskb, 0, ~0, GFP_ATOMIC);
}
#endif /* CONFIG_WEB100_NETLINK */

extern __u32 sysctl_wmem_default;
extern __u32 sysctl_rmem_default;

/* Called whenever a TCP/IPv4 sock is created.
 * net/ipv4/tcp_ipv4.c: tcp_v4_syn_recv_sock,
 *			tcp_v4_init_sock
 * Allocates a stats structure and initializes values.
 */
int web100_stats_create(struct sock *sk)
{
	struct web100stats *stats;
	struct web100directs *vars;
	struct tcp_sock *tp = tcp_sk(sk);
	struct timeval tv;
	
	if ((stats = kmalloc(sizeof (struct web100stats), gfp_any())) == NULL)
		return -ENOMEM;
	tp->tcp_stats = stats;
	vars = &stats->wc_vars;
	
	memset(stats, 0, sizeof (struct web100stats));
	
	stats->wc_cid = -1;
	stats->wc_sk = sk;
	atomic_set(&stats->wc_users, 0);
	
	stats->wc_limstate = WC_SNDLIM_STARTUP;
	stats->wc_limstate_time = web100_mono_time();
	
	vars->NagleEnabled = !(tp->nonagle);
	vars->ActiveOpen = !in_interrupt();
	
	vars->SndUna = tp->snd_una;
	vars->SndNxt = tp->snd_nxt;
	vars->SndMax = tp->snd_nxt;
	vars->SndISS = tp->snd_nxt;
	
	do_gettimeofday(&tv);
	vars->StartTime = tv.tv_sec * 10 + tv.tv_usec / 100000;
	vars->StartTimeSec = tv.tv_sec;
	vars->StartTimeUsec = tv.tv_usec;
	stats->wc_start_monotime = web100_mono_time();
	
	vars->MinRTT = vars->MinRTO = vars->MinMSS = vars->MinRwinRcvd =
		vars->MinRwinSent = vars->MinSsthresh = WC_INF32;
	
	vars->LimRwin = tp->window_clamp;
	
	sock_hold(sk);
	web100_stats_use(stats);
	
	return 0;
}

void web100_stats_destroy(struct web100stats *stats)
{
	/* Attribute final sndlim time. */
	web100_update_sndlim(tcp_sk(stats->wc_sk), stats->wc_limstate);
	
	if (stats->wc_cid >= 0) {
#ifdef CONFIG_WEB100_NETLINK
		web100_netlink_event(WC_NL_TYPE_DISCONNECT, stats->wc_cid);
#endif
		stats_persist(stats);
	} else {
		web100_stats_unuse(stats);
	}
}

/* Do not call directly.  Called from web100_stats_unuse(). */
void web100_stats_free(struct web100stats *stats)
{
	if (stats->wc_cid >= 0) {
		stats_unlink(stats);
	}
	sock_put(stats->wc_sk);
	kfree(stats);
}

extern __u32 sysctl_wmem_default;
extern __u32 sysctl_rmem_default;

/* Called when a connection enters the ESTABLISHED state, and has all its
 * state initialized.
 * net/ipv4/tcp_input.c: tcp_rcv_state_process,
 *			 tcp_rcv_synsent_state_process
 * Here we link the statistics structure in so it is visible in the /proc
 * fs, and do some final init.
 */
void web100_stats_establish(struct sock *sk)
{
	struct inet_sock *inet = inet_sk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct web100stats *stats = tp->tcp_stats;
	struct web100directs *vars = &stats->wc_vars;
	
	if (stats == NULL)
		return;
	
	/* Let's set these here, since they can't change once the
	 * connection is established.
	 */
	vars->LocalPort = inet->num;
	vars->RemPort = ntohs(inet->dport);
	
	if (vars->LocalAddressType == WC_ADDRTYPE_IPV4) {
		vars->LocalAddress.v4addr = inet->rcv_saddr;
		vars->RemAddress.v4addr = inet->daddr;
	}
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	else if (vars->LocalAddressType == WC_ADDRTYPE_IPV6) {
		memcpy(&vars->LocalAddress.v6addr.addr, &(inet6_sk(sk)->saddr), 16);
		memcpy(&vars->RemAddress.v6addr.addr, &(inet6_sk(sk)->daddr), 16);
	}
#endif
	else {
		printk(KERN_ERR "Web100: LocalAddressType not valid.\n");
	}
	vars->LocalAddress.v6addr.type = vars->RemAddress.v6addr.type = vars->LocalAddressType;
	
	vars->SACKEnabled = tp->rx_opt.sack_ok;
	vars->TimestampsEnabled = tp->rx_opt.tstamp_ok;
#ifdef CONFIG_INET_ECN
	vars->ECNEnabled = tp->ecn_flags & TCP_ECN_OK;
#endif
	
	if (tp->rx_opt.wscale_ok) {
		vars->WinScaleRcvd = tp->rx_opt.snd_wscale;
		vars->WinScaleSent = tp->rx_opt.rcv_wscale;
	} else {
		vars->WinScaleRcvd = -1;
		vars->WinScaleSent = -1;
	}
	vars->SndWinScale = vars->WinScaleRcvd;
	vars->RcvWinScale = vars->WinScaleSent;
	
	vars->CurCwnd = tp->snd_cwnd * tp->mss_cache;
	vars->CurSsthresh = tp->snd_ssthresh * tp->mss_cache;
	web100_update_cwnd(tp);
	web100_update_rwin_rcvd(tp);
	web100_update_rwin_sent(tp);
	
	vars->RecvISS = vars->RcvNxt = tp->rcv_nxt;
	
	vars->RetranThresh = tp->reordering;
	
	vars->LimRwin = min_t(__u32, vars->LimRwin, 65355U << tp->rx_opt.rcv_wscale);
	
	stats_link(stats);
	
	web100_update_sndlim(tp, WC_SNDLIM_SENDER);
	
#ifdef CONFIG_WEB100_NETLINK
	web100_netlink_event(WC_NL_TYPE_CONNECT, stats->wc_cid);
#endif
}

/*
 * Statistics update functions
 */

void web100_update_snd_nxt(struct tcp_sock *tp)
{
	struct web100stats *stats = tp->tcp_stats;
	
	if (after(tp->snd_nxt, stats->wc_vars.SndMax)) {
		if (before(stats->wc_vars.SndMax, stats->wc_vars.SndISS) &&
		    after(tp->snd_nxt, stats->wc_vars.SndISS))
			stats->wc_vars.SendWraps++;
		stats->wc_vars.SndMax = tp->snd_nxt;
	}
	stats->wc_vars.SndNxt = tp->snd_nxt;
}

void web100_update_snd_una(struct tcp_sock *tp)
{
	struct web100stats *stats = tp->tcp_stats;
	
	stats->wc_vars.ThruBytesAcked += (__u32)(tp->snd_una - stats->wc_vars.SndUna);
	stats->wc_vars.SndUna = tp->snd_una;
}

void web100_update_rtt(struct sock *sk, unsigned long rtt_sample)
{
	struct web100stats *stats = tcp_sk(sk)->tcp_stats;
        unsigned long rtt_sample_msec = rtt_sample * 1000 / HZ;
        __u32 rto;
	
	stats->wc_vars.SampleRTT = rtt_sample_msec;

	if (rtt_sample_msec > stats->wc_vars.MaxRTT)
	        stats->wc_vars.MaxRTT = rtt_sample_msec;
	if (rtt_sample_msec < stats->wc_vars.MinRTT)
		stats->wc_vars.MinRTT = rtt_sample_msec;
	
	stats->wc_vars.CountRTT++;
	stats->wc_vars.SumRTT += rtt_sample_msec;

	if (stats->wc_vars.PreCongCountRTT != stats->wc_vars.PostCongCountRTT) {
		stats->wc_vars.PostCongCountRTT++;
		stats->wc_vars.PostCongSumRTT += rtt_sample_msec;
	}
	
	/* srtt is stored as 8 * the smoothed estimate */
	stats->wc_vars.SmoothedRTT =
		(tcp_sk(sk)->srtt >> 3) * 1000 / HZ;
	
	rto = inet_csk(sk)->icsk_rto * 1000 / HZ;
	if (rto > stats->wc_vars.MaxRTO)
		stats->wc_vars.MaxRTO = rto;
	if (rto < stats->wc_vars.MinRTO)
		stats->wc_vars.MinRTO = rto;
	stats->wc_vars.CurRTO = rto;

	stats->wc_vars.CurTimeoutCount = 0;
	
	stats->wc_vars.RTTVar = (tcp_sk(sk)->rttvar >> 2) * 1000 / HZ;
}

void web100_update_timeout(struct sock *sk) {
	struct web100stats *stats = tcp_sk(sk)->tcp_stats;

	stats->wc_vars.CurTimeoutCount++;
	if (inet_csk(sk)->icsk_backoff)
		stats->wc_vars.SubsequentTimeouts++;
	else
		stats->wc_vars.Timeouts++;
	if (inet_csk(sk)->icsk_ca_state == TCP_CA_Open)
		stats->wc_vars.AbruptTimeouts++;
}

void web100_update_mss(struct tcp_sock *tp)
{
	struct web100stats *stats = tp->tcp_stats;
	int mss = tp->mss_cache;
	
	stats->wc_vars.CurMSS = mss;
	if (mss > stats->wc_vars.MaxMSS)
		stats->wc_vars.MaxMSS = mss;
	if (mss < stats->wc_vars.MinMSS)
		stats->wc_vars.MinMSS = mss;
}

void web100_update_cwnd(struct tcp_sock *tp)
{
	struct web100stats *stats = tp->tcp_stats;
	__u16 mss = tp->mss_cache;
	__u32 cwnd;
	__u32 ssthresh;
	
	if (mss == 0) {
		printk("Web100: web100_update_cwnd: mss == 0\n");
		return;
	}
	
	cwnd = min(WC_INF32 / mss, tp->snd_cwnd) * mss;
	stats->wc_vars.CurCwnd = cwnd;
	if (cwnd > stats->wc_vars.MaxCwnd)
		stats->wc_vars.MaxCwnd = cwnd;
	
	ssthresh = min(WC_INF32 / mss, tp->snd_ssthresh) * mss;
	stats->wc_vars.CurSsthresh = ssthresh;
	
	/* Discard initiail ssthresh set at infinity. */
	if (tp->snd_ssthresh >= 0x7ffffff) {
		return;
	}
	if (ssthresh > stats->wc_vars.MaxSsthresh)
		stats->wc_vars.MaxSsthresh = ssthresh;
	if (ssthresh < stats->wc_vars.MinSsthresh)
		stats->wc_vars.MinSsthresh = ssthresh;
}

void web100_update_rwin_rcvd(struct tcp_sock *tp)
{
	struct web100stats *stats = tp->tcp_stats;
	__u32 win = tp->snd_wnd;
	
	stats->wc_vars.CurRwinRcvd = win;
	if (win > stats->wc_vars.MaxRwinRcvd)
		stats->wc_vars.MaxRwinRcvd = win;
	if (win < stats->wc_vars.MinRwinRcvd)
		stats->wc_vars.MinRwinRcvd = win;
}

void web100_update_rwin_sent(struct tcp_sock *tp)
{
	struct web100stats *stats = tp->tcp_stats;
	__u32 win = tp->rcv_wnd;

	/* Update our advertised window. */
	stats->wc_vars.CurRwinSent = win;
	if (win > stats->wc_vars.MaxRwinSent)
		stats->wc_vars.MaxRwinSent = win;
	if (win < stats->wc_vars.MinRwinSent)
		stats->wc_vars.MinRwinSent = win;
}


/* TODO: change this to a generic state machine instrument */
static void web100_state_update(struct tcp_sock *tp, int why, __u64 bytes)
{
	struct web100stats *stats = tp->tcp_stats;
	__u64 now;
	
	now = web100_mono_time();
	stats->wc_vars.SndLimTime[stats->wc_limstate] += now - stats->wc_limstate_time;
	stats->wc_limstate_time = now;
	
	stats->wc_vars.SndLimBytes[why] += bytes - stats->wc_limstate_bytes;
	stats->wc_limstate_bytes = bytes;
	
	if (stats->wc_limstate != why) {
		stats->wc_limstate = why;
		stats->wc_vars.SndLimTrans[why]++;
	}
}

void web100_update_sndlim(struct tcp_sock *tp, int why)
{
	struct web100stats *stats = tp->tcp_stats;
	
	if (why < 0) {
		printk("web100_update_sndlim: BUG: why < 0\n");
		return;
	}
	
	web100_state_update(tp, why, stats->wc_vars.DataBytesOut);
	/* future instruments on other sender bottlenecks here... */
	/* if (!why) { why = ??? } */
	/* web100_state_update(tp, why, stats->wc_vars.DataBytesOut); */
}

void web100_update_congestion(struct tcp_sock *tp, int why_dummy)
{
       	struct web100stats *stats = tp->tcp_stats;
	
	stats->wc_vars.CongestionSignals++;
	stats->wc_vars.PreCongSumCwnd += stats->wc_vars.CurCwnd;

	/* This may require more control flags */
	stats->wc_vars.PreCongCountRTT++;
	stats->wc_vars.PreCongSumRTT += stats->wc_vars.SampleRTT;
}

/* Called from tcp_transmit_skb, whenever we push a segment onto the wire.
 */
void web100_update_segsend(struct sock *sk, int len, int pcount,
                           __u32 seq, __u32 end_seq, int flags)
{
	struct web100stats *stats = tcp_sk(sk)->tcp_stats;
	
	/* We know we're sending a segment. */
	stats->wc_vars.PktsOut += pcount;
	
	/* We know the ack seq is rcv_nxt. web100_XXX bug compatible*/
	web100_update_rcv_nxt(tcp_sk(sk));
	
	/* A pure ACK contains no data; everything else is data. */
	if (len > 0) {
		stats->wc_vars.DataPktsOut += pcount;
		stats->wc_vars.DataBytesOut += len;
	} else {
		stats->wc_vars.AckPktsOut++;
	}
	
	/* Check for retransmission. */
	if (flags & TCPCB_FLAG_SYN) {
		if (inet_csk(sk)->icsk_retransmits)
			stats->wc_vars.PktsRetrans++;
	} else if (before(seq, stats->wc_vars.SndMax)) {
		stats->wc_vars.PktsRetrans += pcount;
		stats->wc_vars.BytesRetrans += end_seq - seq;
	}
}

void web100_update_segrecv(struct tcp_sock *tp, struct sk_buff *skb)
{
	struct web100directs *vars = &tp->tcp_stats->wc_vars;
	struct tcphdr *th = tcp_hdr(skb);
	
	vars->PktsIn++;
	if (skb->len == th->doff*4) {
		vars->AckPktsIn++;
		if (TCP_SKB_CB(skb)->ack_seq == tp->snd_una)
			vars->DupAcksIn++;
	} else {
		vars->DataPktsIn++;
		vars->DataBytesIn += skb->len - th->doff*4;
	}
}

void web100_update_rcv_nxt(struct tcp_sock *tp)
{
	struct web100stats *stats = tp->tcp_stats;
	
	if (before(stats->wc_vars.RcvNxt, stats->wc_vars.RecvISS) &&
	     after(tp->rcv_nxt, stats->wc_vars.RecvISS))
		stats->wc_vars.RecvWraps++;
	stats->wc_vars.ThruBytesReceived += (__u32) (tp->rcv_nxt - stats->wc_vars.RcvNxt); /* XXX */
	stats->wc_vars.RcvNxt = tp->rcv_nxt;
}

void web100_update_writeq(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct web100directs *vars = &tp->tcp_stats->wc_vars;
	int len = tp->write_seq - vars->SndMax;
	
	vars->CurAppWQueue = len;
	if (len > vars->MaxAppWQueue)
		vars->MaxAppWQueue = len;
}

void web100_update_recvq(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct web100directs *vars = &tp->tcp_stats->wc_vars;
	int len1 = tp->rcv_nxt - tp->copied_seq;
	
	vars->CurAppRQueue = len1;
	if (vars->MaxAppRQueue < len1)
		vars->MaxAppRQueue = len1;
	
#if 0 /* FIXME!! */
	vars->CurReasmQueue = len2;
	if (vars->MaxReasmQueue < len2)
		vars->MaxReasmQueue = len2;
#endif
}


void __init web100_stats_init()
{
	int order;
	
	memset(death_slots, 0, sizeof (death_slots));
	
	web100stats_htsize = tcp_hashinfo.ehash_size;
	for (order = 0; (1UL << order) * PAGE_SIZE < web100stats_htsize *
	     sizeof (struct web100stats *); order++)
		;
	printk("Web100: initiailizing hash table of size %d (order %d)\n",
	       web100stats_htsize, order);
	if ((web100stats_ht = (struct web100stats **)__get_free_pages(GFP_ATOMIC, order)) == NULL)
		panic("Failed to allocate Web100 stats hash table.\n");
	memset(web100stats_ht, 0, web100stats_htsize * sizeof (struct web100stats *));
	
#ifdef CONFIG_WEB100_NETLINK
	if ((web100_nlsock = netlink_kernel_create(NETLINK_WEB100, 0, NULL, NULL, NULL)) == NULL)
		printk(KERN_ERR "web100_stats_init(): cannot initialize netlink socket\n");
#endif
	
	printk("Web100 %s: Initialization successful\n", web100_version_string);
}

#ifdef CONFIG_IPV6_MODULE
EXPORT_SYMBOL(web100_stats_create);
EXPORT_SYMBOL(web100_stats_destroy);
EXPORT_SYMBOL(web100_update_segrecv);
EXPORT_SYMBOL(web100_update_cwnd);
EXPORT_SYMBOL(web100_update_writeq);
#endif
