/*
 * include/net/web100_stats.h
 *
 * Copyright (C) 2001 Matt Mathis <mathis@psc.edu>
 * Copyright (C) 2001 John Heffner <jheffner@psc.edu>
 * Copyright (C) 2000 Jeff Semke <semke@psc.edu>
 *
 * The Web 100 project.  See http://www.web100.org
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

/* TODO: make sure that the time duration states below include:
   Congestion Avoidance, Slow Start, Timeouts, Idle Application, and
   Window Limited cases */
/* TODO: Consider adding sysctl variable to enable/disable WC stats updates.
   Probably should still create stats structures if compiled with WC support,
   even if sysctl(wc) is turned off.  That would allow the stats to be updated
   if the sysctl(wc) is turned back on. */
/* TODO: Add all variables needed to do user-level auto-tuning, including
   writeable parameters */


#ifndef _WEB100_STATS_H
#define _WEB100_STATS_H

enum wc_sndlim_states {
	WC_SNDLIM_NONE = -1,
	WC_SNDLIM_SENDER,
	WC_SNDLIM_CWND,
	WC_SNDLIM_RWIN,
	WC_SNDLIM_STARTUP,
	WC_SNDLIM_NSTATES	/* Keep at end */
};

#ifndef CONFIG_WEB100_STATS

#define WEB100_VAR_INC(tp,var)		do {} while (0)
#define WEB100_VAR_DEC(tp,var)		do {} while (0)
#define WEB100_VAR_SET(tp,var,val)	do {} while (0)
#define WEB100_VAR_ADD(tp,var,val)	do {} while (0)
#define WEB100_UPDATE_FUNC(tp,func)	do {} while (0)
#define NET100_WAD(tp, var, def)	(def)

#else /* CONFIG_WEB100_STATS */ /* { */

#include <linux/spinlock.h>

#define WEB100_CHECK(tp,expr) \
	do { if ((tp)->tcp_stats) (expr); } while (0)
#define WEB100_VAR_INC(tp,var) \
	WEB100_CHECK(tp, ((tp)->tcp_stats->wc_vars.var)++)
#define WEB100_VAR_DEC(tp,var) \
	WEB100_CHECK(tp, ((tp)->tcp_stats->wc_vars.var)--)
#define WEB100_VAR_ADD(tp,var,val) \
	WEB100_CHECK(tp, ((tp)->tcp_stats->wc_vars.var) += (val))
#define WEB100_VAR_SET(tp,var,val) \
	WEB100_CHECK(tp, ((tp)->tcp_stats->wc_vars.var) = (val))
#define WEB100_UPDATE_FUNC(tp,func) \
	WEB100_CHECK(tp, func)
#ifdef CONFIG_WEB100_NET100
#define NET100_WAD(tp, var, def) \
	(((tp)->tcp_stats && (tp)->tcp_stats->wc_vars.var) ? (tp)->tcp_stats->wc_vars.var : (def))
#else
#define NET100_WAD(tp, var, def)	(def)
#endif

/* SMIv2 types - RFC 1902 */
typedef __s32		INTEGER;
typedef INTEGER		Integer32;
typedef __u32		IpAddress;
typedef __u32		Counter32;
typedef __u32		Unsigned32;
typedef Unsigned32	Gauge32;
typedef __u32		TimeTicks;
typedef __u64		Counter64;
typedef __u16		Unsigned16;

/* New inet address types specified in INET-ADDRESS-MIB */
typedef Unsigned16	InetPortNumber;
typedef enum {
	WC_ADDRTYPE_UNKNOWN = 0,
	WC_ADDRTYPE_IPV4,
	WC_ADDRTYPE_IPV6,
	WC_ADDRTYPE_DNS = 16
} InetAddressType;
typedef IpAddress	InetAddresIPv4;
typedef struct {
	__u8	addr[16];
	__u8	type;
} InetAddresIPv6;
typedef union {
	InetAddresIPv4	v4addr;
	InetAddresIPv6	v6addr;
} InetAddress;

typedef enum {
	truthValueTrue = 1,
	truthValueFalse = 2
} TruthValue;

enum wc_states {
	WC_STATE_CLOSED = 1,
	WC_STATE_LISTEN,
	WC_STATE_SYNSENT,
	WC_STATE_SYNRECEIVED,
	WC_STATE_ESTABLISHED,
	WC_STATE_FINWAIT1,
	WC_STATE_FINWAIT2,
	WC_STATE_CLOSEWAIT,
	WC_STATE_LASTACK,
	WC_STATE_CLOSING,
	WC_STATE_TIMEWAIT,
	WC_STATE_DELETECB
};

enum wc_stunemodes {
	WC_STUNEMODE_DEFAULT = 0,	/* OS native */
	WC_STUNEMODE_SETSOCKOPT,	/* OS native setsockopt() */
	WC_STUNEMODE_FIXED,		/* Manual via the web100 API */
	WC_STUNEMODE_AUTO,
	WC_STUNEMODE_EXP1,
	WC_STUNEMODE_EXP2
};

enum wc_rtunemodes {
	WC_RTUNEMODE_DEFAULT = 0,
	WC_RTUNEMODE_SETSOCKOPT,
	WC_RTUNEMODE_FIXED,
	WC_RTUNEMODE_AUTO,
	WC_RTUNEMODE_EXP1,
	WC_RTUNEMODE_EXP2
};

enum wc_bufmodes {
	WC_BUFMODE_OS = 0,
	WC_BUFMODE_WEB100,
};

enum {
	WC_SE_BELOW_DATA_WINDOW = 1,
	WC_SE_ABOVE_DATA_WINDOW,
	WC_SE_BELOW_ACK_WINDOW,
	WC_SE_ABOVE_ACK_WINDOW,
	WC_SE_BELOW_TSW_WINDOW,
	WC_SE_ABOVE_TSW_WINDOW,
	WC_SE_DATA_CHECKSUM
};


/*
 * Variables that can be read and written directly.
 * 
 * Should contain most variables from TCP-KIS 0.1.  Commented feilds are
 * either not implemented or have handlers and do not need struct storage.
 */
struct web100directs {
	/* STATE */
	INTEGER		State;
	TruthValue	SACKEnabled;
	TruthValue	TimestampsEnabled;
	TruthValue	NagleEnabled;
	TruthValue	ECNEnabled;
	Integer32	SndWinScale;
	Integer32	RcvWinScale;
	
	/* SYN OPTIONS */
	INTEGER		ActiveOpen;
     /* Gauge32		MSSSent; */
	Gauge32		MSSRcvd;
	Integer32	WinScaleRcvd;
	Integer32	WinScaleSent;
     /* INTEGER		SACKokSent; */
     /* INTEGER		SACKokRcvd; */
     /* INTEGER		TimestampSent; */
     /* INTEGER		TimestampRcvd; */
	
	/* DATA */
	Counter32	PktsOut;
	Counter32	DataPktsOut;
	Counter32	AckPktsOut;		/* DEPRICATED */
	Counter64	DataBytesOut;
	Counter32	PktsIn;
	Counter32	DataPktsIn;
	Counter32	AckPktsIn;		/* DEPRICATED */
	Counter64	DataBytesIn;
     /* Counter32	SoftErrors; */
     /* INTEGER		SoftErrorReason; */
	Counter32	SndUna;
	Unsigned32	SndNxt;
	Counter32	SndMax;
	Counter64	ThruBytesAcked;
	Counter32	SndISS;			/* SndInitial */
	Counter32	SendWraps;		/* DEPRICATED */
	Counter32	RcvNxt;
	Counter64	ThruBytesReceived;
	Counter32	RecvISS;		/* RecInitial */
	Counter32	RecvWraps;		/* DEPRICATED */
     /* Counter64	Duration; */
	Integer32	StartTime;		/* DEPRICATED */
	Integer32	StartTimeSec;
	Integer32	StartTimeUsec;

	/* SENDER CONGESTION */
	Counter32	SndLimTrans[WC_SNDLIM_NSTATES];
	Counter32	SndLimTime[WC_SNDLIM_NSTATES];
	Counter64	SndLimBytes[WC_SNDLIM_NSTATES];
	Counter32	SlowStart;
	Counter32	CongAvoid;
	Counter32	CongestionSignals;
	Counter32	OtherReductions;
	Counter32	X_OtherReductionsCV;
	Counter32	X_OtherReductionsCM;
	Counter32	CongestionOverCount;
	Gauge32		CurCwnd;
	Gauge32		MaxCwnd;
     /* Gauge32		LimCwnd; */
	Gauge32		CurSsthresh;
	Gauge32		MaxSsthresh;
	Gauge32		MinSsthresh;

	/* SENDER PATH MODEL */
	Counter32	FastRetran;
	Counter32	Timeouts;
	Counter32	SubsequentTimeouts;
	Gauge32		CurTimeoutCount;
	Counter32	AbruptTimeouts;
	Counter32	PktsRetrans;
	Counter32	BytesRetrans;
	Counter32	DupAcksIn;
	Counter32	SACKsRcvd;
     	Counter32	SACKBlocksRcvd;
     	Counter32	PreCongSumCwnd;
	Counter32	PreCongSumRTT;
	Counter32	PreCongCountRTT;	/* DEPRICATED */
	Counter32	PostCongSumRTT;
	Counter32	PostCongCountRTT;
     /* Counter32	ECNsignals; */
	Counter32	ECERcvd;
	Counter32	SendStall;
	Counter32	QuenchRcvd;
	Gauge32		RetranThresh;
     /* Counter32	SndDupAckEpisodes; */
     /* Counter64	SumBytesReordered; */
	Counter32	NonRecovDA;
	Counter32	AckAfterFR;
	Counter32	DSACKDups;
	Gauge32		SampleRTT;
	Gauge32		SmoothedRTT;
	Gauge32		RTTVar;
	Gauge32		MaxRTT;
	Gauge32		MinRTT;
	Counter64	SumRTT;
	Counter32	CountRTT;
	Gauge32		CurRTO;
	Gauge32		MaxRTO;
	Gauge32		MinRTO;
	Gauge32		CurMSS;
	Gauge32		MaxMSS;
	Gauge32		MinMSS;

	/* LOCAL SENDER BUFFER */
	Gauge32		CurRetxQueue;
	Gauge32		MaxRetxQueue;
	Gauge32		CurAppWQueue;
	Gauge32		MaxAppWQueue;

	/* LOCAL RECEIVER */
	Gauge32		CurRwinSent;
	Gauge32		MaxRwinSent;
	Gauge32		MinRwinSent;
	Integer32	LimRwin;
     /* Counter32	DupAckEpisodes; */
	Counter32	DupAcksOut;
     /* Counter32	CERcvd; */
     /* Counter32	ECNSent; */
     /* Counter32	ECNNonceRcvd; */
	Gauge32		CurReasmQueue;
	Gauge32		MaxReasmQueue;
	Gauge32		CurAppRQueue;
	Gauge32		MaxAppRQueue;
	Gauge32		X_rcv_ssthresh;
	Gauge32		X_wnd_clamp;
	Gauge32		X_dbg1;
	Gauge32		X_dbg2;
	Gauge32		X_dbg3;
	Gauge32		X_dbg4;

	/* OBSERVED RECEIVER */
	Gauge32		CurRwinRcvd;
	Gauge32		MaxRwinRcvd;
	Gauge32		MinRwinRcvd;

	/* CONNECTION ID */
	InetAddressType	LocalAddressType;
	InetAddress	LocalAddress;
	InetPortNumber	LocalPort;
     /* InetAddressType	RemAddressType;	*/
	InetAddress	RemAddress;
	InetPortNumber	RemPort;
     /* Integer32	IdId; */
	
	Gauge32		X_RcvRTT;
	
#ifdef CONFIG_WEB100_NET100
	/* support for the NET100 Work Around Deamon (WAD) */
	Gauge32		WAD_IFQ;
	Gauge32		WAD_MaxBurst;
	Gauge32         WAD_MaxSsthresh;
	INTEGER		WAD_NoAI;
	Integer32	WAD_CwndAdjust;
#endif
};

struct web100stats {
	int			wc_cid;
	
	struct sock		*wc_sk;
	
	atomic_t		wc_users;
	__u8			wc_dead;
	
	struct web100stats	*wc_next;
	struct web100stats	*wc_prev;
	
	struct web100stats	*wc_hash_next;
	struct web100stats	*wc_hash_prev;
	
	struct web100stats	*wc_death_next;
	
	int			wc_limstate;
	__u64			wc_limstate_bytes;
	__u64			wc_limstate_time;
	
	__u64			wc_start_monotime;
	
	struct web100directs	wc_vars;
};

#endif /* CONFIG_WEB100_STATS */ /* } */

#endif		/*_WEB100_STATS_H */
