/* 
 *  include/net/web100.h
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

#ifndef _WEB100_H
#define _WEB100_H

#include <net/sock.h>
#include <net/web100_stats.h>
#include <linux/tcp.h>

#ifdef CONFIG_WEB100_STATS

#define WEB100_MAX_CONNS	(1<<15)

#define WEB100_DELAY_MAX	HZ

/* Netlink */
#define WC_NL_TYPE_CONNECT	0
#define WC_NL_TYPE_DISCONNECT	1

struct web100_netlink_msg {
	int type;
	int cid;
};

/* The syntax of this version string is subject to future changes */
extern char *web100_version_string;

/* Stats structures */
extern struct web100stats *web100stats_arr[];
extern struct web100stats *web100stats_first;

/* For locking the creation and destruction of stats structures. */
extern rwlock_t web100_linkage_lock;

/* For /proc/web100 */
extern struct web100stats *web100stats_lookup(int cid);

/* For the TCP code */
extern int  web100_stats_create(struct sock *sk);
extern void web100_stats_destroy(struct web100stats *stats);
extern void web100_stats_free(struct web100stats *stats);
extern void web100_stats_establish(struct sock *sk);

extern void web100_tune_sndbuf_ack(struct sock *sk);
extern void web100_tune_sndbuf_snd(struct sock *sk);
extern void web100_tune_rcvbuf(struct sock *sk);

extern void web100_update_snd_nxt(struct tcp_sock *tp);
extern void web100_update_snd_una(struct tcp_sock *tp);
extern void web100_update_rtt(struct sock *sk, unsigned long rtt_sample);
extern void web100_update_timeout(struct sock *sk);
extern void web100_update_mss(struct tcp_sock *tp);
extern void web100_update_cwnd(struct tcp_sock *tp);
extern void web100_update_rwin_rcvd(struct tcp_sock *tp);
extern void web100_update_sndlim(struct tcp_sock *tp, int why);
extern void web100_update_rcv_nxt(struct tcp_sock *tp);
extern void web100_update_rwin_sent(struct tcp_sock *tp);
extern void web100_update_congestion(struct tcp_sock *tp, int why);
extern void web100_update_segsend(struct sock *sk, int len, int pcount,
                                  __u32 seq, __u32 end_seq, int flags);
extern void web100_update_segrecv(struct tcp_sock *tp, struct sk_buff *skb);
extern void web100_update_rcvbuf(struct sock *sk, int rcvbuf);
extern void web100_update_writeq(struct sock *sk);
extern void web100_update_recvq(struct sock *sk);
extern void web100_update_ofoq(struct sock *sk);

extern void web100_stats_init(void);

/* For the IP code */
extern int web100_delay_output(struct sk_buff *skb, int (*output)(struct sk_buff *));

extern __u64 web100_mono_time(void);

/* You may have to hold web100_linkage_lock here to prevent
   stats from disappearing. */
static inline void web100_stats_use(struct web100stats *stats)
{
	atomic_inc(&stats->wc_users);
}

/* You MUST NOT hold web100_linkage_lock here. */
static inline void web100_stats_unuse(struct web100stats *stats)
{
	if (atomic_dec_and_test(&stats->wc_users))
		web100_stats_free(stats);
}

/* A mapping between Linux and Web100 states.  This could easily just
 * be an array. */
static inline int web100_state(int state)
{
	switch (state) {
	case TCP_ESTABLISHED:	return WC_STATE_ESTABLISHED;
	case TCP_SYN_SENT:	return WC_STATE_SYNSENT;
	case TCP_SYN_RECV:	return WC_STATE_SYNRECEIVED;
	case TCP_FIN_WAIT1:	return WC_STATE_FINWAIT1;
	case TCP_FIN_WAIT2:	return WC_STATE_FINWAIT2;
	case TCP_TIME_WAIT:	return WC_STATE_TIMEWAIT;
	case TCP_CLOSE:		return WC_STATE_CLOSED;
	case TCP_CLOSE_WAIT:	return WC_STATE_CLOSEWAIT;
	case TCP_LAST_ACK:	return WC_STATE_LASTACK;
	case TCP_LISTEN:	return WC_STATE_LISTEN;
	case TCP_CLOSING:	return WC_STATE_CLOSING;
	default:		return 0;
	}
}

#endif /* CONFIG_WEB100_STATS */

#endif /* _WEB100_H */
