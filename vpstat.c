/**
* Nine (formerly SuperVault Cloud or SV Cloud)
* Copyright (c), 2010, Nine Technology, Inc. (formerly Vault USA, LLC)
*
* vdaemon port stat
*
* Author(s): wxlin  <weixuan.lin@sierraatlantic.com>
*
* $Id:vstat.h,v 1.4 2008-12-30 08:14:55 wxlin Exp $
*
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <dirent.h>
#include <ctype.h>
#include <time.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <sched.h>
#include <pwd.h>
#include <grp.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/vfs.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <net/if.h>
#include <sys/utsname.h>
#include <linux/sockios.h>
#include <sys/resource.h>
#include <pcap.h>
#include <pthread.h>
#include <ncurses.h>

#define HZ 1000
#define INT_MAX 2147483647 
#define PRG_LOCAL_ADDRESS "local_address"
#define PRG_INODE		  "inode"
#define PRG_SOCKET_PFX    "socket:["
#define PRG_SOCKET_PFXl   (strlen(PRG_SOCKET_PFX))
#define PRG_SOCKET_PFX2   "[0000]:"
#define PRG_SOCKET_PFX2l  (strlen(PRG_SOCKET_PFX2))
#define MALLOC(TYPE)	  calloc(1,sizeof(TYPE))

/* CMDs currently supported */
#define ETHTOOL_GSET		0x00000001 /* Get settings. */
#define ETHTOOL_SSET		0x00000002 /* Set settings. */
#define ETHTOOL_GDRVINFO	0x00000003 /* Get driver info. */
#define ETHTOOL_GREGS		0x00000004 /* Get NIC registers. */
#define ETHTOOL_GWOL		0x00000005 /* Get wake-on-lan options. */
#define ETHTOOL_SWOL		0x00000006 /* Set wake-on-lan options. */
#define ETHTOOL_GMSGLVL		0x00000007 /* Get driver message level */
#define ETHTOOL_SMSGLVL		0x00000008 /* Set driver msg level. */
#define ETHTOOL_NWAY_RST	0x00000009 /* Restart autonegotiation. */
#define ETHTOOL_GLINK		0x0000000a /* Get link status (ethtool_value) */
#define ETHTOOL_GEEPROM		0x0000000b /* Get EEPROM data */
#define ETHTOOL_SEEPROM		0x0000000c /* Set EEPROM data. */
#define ETHTOOL_GCOALESCE	0x0000000e /* Get coalesce config */
#define ETHTOOL_SCOALESCE	0x0000000f /* Set coalesce config. */
#define ETHTOOL_GRINGPARAM	0x00000010 /* Get ring parameters */
#define ETHTOOL_SRINGPARAM	0x00000011 /* Set ring parameters. */
#define ETHTOOL_GPAUSEPARAM	0x00000012 /* Get pause parameters */
#define ETHTOOL_SPAUSEPARAM	0x00000013 /* Set pause parameters. */
#define ETHTOOL_GRXCSUM		0x00000014 /* Get RX hw csum enable (ethtool_value) */
#define ETHTOOL_SRXCSUM		0x00000015 /* Set RX hw csum enable (ethtool_value) */
#define ETHTOOL_GTXCSUM		0x00000016 /* Get TX hw csum enable (ethtool_value) */
#define ETHTOOL_STXCSUM		0x00000017 /* Set TX hw csum enable (ethtool_value) */
#define ETHTOOL_GSG			0x00000018 /* Get scatter-gather enable
* (ethtool_value) */
#define ETHTOOL_SSG			0x00000019 /* Set scatter-gather enable
* (ethtool_value). */
#define ETHTOOL_TEST		0x0000001a /* execute NIC self-test. */
#define ETHTOOL_GSTRINGS	0x0000001b /* get specified string set */
#define ETHTOOL_PHYS_ID		0x0000001c /* identify the NIC */
#define ETHTOOL_GSTATS		0x0000001d /* get NIC-specific statistics */
#define ETHTOOL_GTSO		0x0000001e /* Get TSO enable (ethtool_value) */
#define ETHTOOL_STSO		0x0000001f /* Set TSO enable (ethtool_value) */
#define ETHTOOL_GPERMADDR	0x00000020 /* Get permanent hardware address */
#define ETHTOOL_GUFO		0x00000021 /* Get UFO enable (ethtool_value) */
#define ETHTOOL_SUFO		0x00000022 /* Set UFO enable (ethtool_value) */
#define ETHTOOL_GGSO		0x00000023 /* Get GSO enable (ethtool_value) */
#define ETHTOOL_SGSO		0x00000024 /* Set GSO enable (ethtool_value) */

/* compatibility with older code */
#define SPARC_ETH_GSET		ETHTOOL_GSET
#define SPARC_ETH_SSET		ETHTOOL_SSET

/* Indicates what features are supported by the interface. */
#define SUPPORTED_10baseT_Half		(1 << 0)
#define SUPPORTED_10baseT_Full		(1 << 1)
#define SUPPORTED_100baseT_Half		(1 << 2)
#define SUPPORTED_100baseT_Full		(1 << 3)
#define SUPPORTED_1000baseT_Half	(1 << 4)
#define SUPPORTED_1000baseT_Full	(1 << 5)
#define SUPPORTED_Autoneg			(1 << 6)
#define SUPPORTED_TP				(1 << 7)
#define SUPPORTED_AUI				(1 << 8)
#define SUPPORTED_MII				(1 << 9)
#define SUPPORTED_FIBRE				(1 << 10)
#define SUPPORTED_BNC				(1 << 11)
#define SUPPORTED_10000baseT_Full	(1 << 12)
#define SUPPORTED_Pause				(1 << 13)
#define SUPPORTED_Asym_Pause		(1 << 14)
#define SUPPORTED_2500baseX_Full	(1 << 15)

/* Indicates what features are advertised by the interface. */
#define ADVERTISED_10baseT_Half		(1 << 0)
#define ADVERTISED_10baseT_Full		(1 << 1)
#define ADVERTISED_100baseT_Half	(1 << 2)
#define ADVERTISED_100baseT_Full	(1 << 3)
#define ADVERTISED_1000baseT_Half	(1 << 4)
#define ADVERTISED_1000baseT_Full	(1 << 5)
#define ADVERTISED_Autoneg			(1 << 6)
#define ADVERTISED_TP				(1 << 7)
#define ADVERTISED_AUI				(1 << 8)
#define ADVERTISED_MII				(1 << 9)
#define ADVERTISED_FIBRE			(1 << 10)
#define ADVERTISED_BNC				(1 << 11)
#define ADVERTISED_10000baseT_Full	(1 << 12)
#define ADVERTISED_Pause			(1 << 13)
#define ADVERTISED_Asym_Pause		(1 << 14)
#define ADVERTISED_2500baseX_Full	(1 << 15)

/* The following are all involved in forcing a particular link
* mode for the device for setting things.  When getting the
* devices settings, these indicate the current mode and whether
* it was foced up into this mode or autonegotiated.
*/

/* The forced speed, 10Mb, 100Mb, gigabit, 2.5Gb, 10GbE. */
#define SPEED_10		10
#define SPEED_100		100
#define SPEED_1000		1000
#define SPEED_2500		2500
#define SPEED_10000		10000

/* Duplex, half or full. */
#define DUPLEX_HALF		0x00
#define DUPLEX_FULL		0x01

/* Which connector port. */
#define PORT_TP			0x00
#define PORT_AUI		0x01
#define PORT_MII		0x02
#define PORT_FIBRE		0x03
#define PORT_BNC		0x04

/* Which transceiver to use. */
#define XCVR_INTERNAL	0x00
#define XCVR_EXTERNAL	0x01
#define XCVR_DUMMY1		0x02
#define XCVR_DUMMY2		0x03
#define XCVR_DUMMY3		0x04

/* Enable or disable autonegotiation.  If this is set to enable,
* the forced link modes above are completely ignored.
*/
#define AUTONEG_DISABLE	0x00
#define AUTONEG_ENABLE	0x01

/* Wake-On-Lan options. */
#define WAKE_PHY		 (1 << 0)
#define WAKE_UCAST		 (1 << 1)
#define WAKE_MCAST		 (1 << 2)
#define WAKE_BCAST		 (1 << 3)
#define WAKE_ARP		 (1 << 4)
#define WAKE_MAGIC		 (1 << 5)
#define WAKE_MAGICSECURE (1 << 6) /* only meaningful if WAKE_MAGIC */

#define IFA_LINKING		 1
#define IFA_UNLINK		 2
#define IFA_NOLINK		 3

/* hack, so we may include kernel's ethtool.h */
typedef unsigned long long __u64;
typedef __uint32_t __u32;
typedef __uint16_t __u16;
typedef __uint8_t __u8;

/* historical: we used to use kernel-like types; remove these once cleaned */
typedef unsigned long long u64;
typedef __uint32_t u32;
typedef __uint16_t u16;
typedef __uint8_t u8;

typedef __uint32_t u_int32_t;
typedef __uint16_t u_int16_t;
typedef __uint8_t  u_int8_t;

/*  ethernet header define from ether.h*/
#define	ETHERTYPE_PUP		0x0200   
#define	ETHERTYPE_IP		0x0800
#define	ETHERTYPE_ARP		0x0806
#define	ETHERTYPE_REVARP	0x8035
#define	ETHER_ADDR_LEN		6

struct	ether_header {
	u_int8_t	ether_dhost[ETHER_ADDR_LEN];
	u_int8_t	ether_shost[ETHER_ADDR_LEN];
	u_int16_t	ether_type;
};

struct vlan_8021q_header {
	u_int16_t	priority_cfi_vid;
	u_int16_t	ether_type;
};

/*
 * Definitions for internet protocol version 4.
 * Per RFC 791, September 1981.
 */
#define	IPVERSION	4

/*
 * Structure of an internet header, naked of options.
 *
 * We declare ip_len and ip_off to be short, rather than u_short
 * pragmatically since otherwise unsigned comparisons can result
 * against negative integers quite easily, and fail in subtle ways.
 */
struct ip {
	u_int8_t	ip_vhl;		/* header length, version */
#define IP_V(ip)	(((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip)	((ip)->ip_vhl & 0x0f)
	u_int8_t	ip_tos;		/* type of service */
	u_int16_t	ip_len;		/* total length */
	u_int16_t	ip_id;		/* identification */
	u_int16_t	ip_off;		/* fragment offset field */
#define	IP_DF 0x4000		/* dont fragment flag */
#define	IP_MF 0x2000		/* more fragments flag */
#define	IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	u_int8_t	ip_ttl;		/* time to live */
	u_int8_t	ip_p;		/* protocol */
	u_int16_t	ip_sum;		/* checksum */
	struct	in_addr ip_src,ip_dst;	/* source and dest address */
};

#define	IP_MAXPACKET	65535		/* maximum packet size */

/*
 * Definitions for IP type of service (ip_tos)
 */
#define	IPTOS_LOWDELAY				0x10
#define	IPTOS_THROUGHPUT			0x08
#define	IPTOS_RELIABILITY			0x04

/*
 * Definitions for IP precedence (also in ip_tos) (hopefully unused)
 */
#define	IPTOS_PREC_NETCONTROL		0xe0
#define	IPTOS_PREC_INTERNETCONTROL	0xc0
#define	IPTOS_PREC_CRITIC_ECP		0xa0
#define	IPTOS_PREC_FLASHOVERRIDE	0x80
#define	IPTOS_PREC_FLASH			0x60
#define	IPTOS_PREC_IMMEDIATE		0x40
#define	IPTOS_PREC_PRIORITY			0x20
#define	IPTOS_PREC_ROUTINE			0x00

/*
 * Definitions for options.
 */
#define	IPOPT_COPIED(o)		((o)&0x80)
#define	IPOPT_CLASS(o)		((o)&0x60)
#define	IPOPT_NUMBER(o)		((o)&0x1f)

#define	IPOPT_CONTROL		0x00
#define	IPOPT_RESERVED1		0x20
#define	IPOPT_DEBMEAS		0x40
#define	IPOPT_RESERVED2		0x60

#define	IPOPT_EOL		0		/* end of option list */
#define	IPOPT_NOP		1		/* no operation */
#define	IPOPT_RR		7		/* record packet route */
#define	IPOPT_TS		68		/* timestamp */
#define	IPOPT_SECURITY	130		/* provide s,c,h,tcc */
#define	IPOPT_LSRR		131		/* loose source route */
#define	IPOPT_SATID		136		/* satnet id */
#define	IPOPT_SSRR		137		/* strict source route */

/*
 * Offsets to fields in options other than EOL and NOP.
 */
#define	IPOPT_OPTVAL	0		/* option ID */
#define	IPOPT_OLEN		1		/* option length */
#define IPOPT_OFFSET	2		/* offset within option */
#define	IPOPT_MINOFF	4		/* min value of above */

/*
 * Time stamp option structure.
 */
struct	ip_timestamp {
	u_int8_t	ipt_code;		/* IPOPT_TS */
	u_int8_t	ipt_len;		/* size of structure (variable) */
	u_int8_t	ipt_ptr;		/* index of current entry */
	u_int8_t	ipt_oflwflg;	/* flags, overflow counter */
#define IPTS_OFLW(ip)	(((ipt)->ipt_oflwflg & 0xf0) >> 4)
#define IPTS_FLG(ip)	((ipt)->ipt_oflwflg & 0x0f)
	union ipt_timestamp {
		u_int32_t ipt_time[1];
		struct	ipt_ta {
			struct in_addr ipt_addr;
			u_int32_t ipt_time;
		} ipt_ta[1];
	} ipt_timestamp;
};

/* flag bits for ipt_flg */
#define	IPOPT_TS_TSONLY		0	/* timestamps only */
#define	IPOPT_TS_TSANDADDR	1	/* timestamps and addresses */
#define	IPOPT_TS_PRESPEC	3	/* specified modules only */

/* bits for security (not byte swapped) */
#define	IPOPT_SECUR_UNCLASS		0x0000
#define	IPOPT_SECUR_CONFID		0xf135
#define	IPOPT_SECUR_EFTO		0x789a
#define	IPOPT_SECUR_MMMM		0xbc4d
#define	IPOPT_SECUR_RESTR		0xaf13
#define	IPOPT_SECUR_SECRET		0xd788
#define	IPOPT_SECUR_TOPSECRET	0x6bc5

/*
 * Internet implementation parameters.
 */
#define	MAXTTL		255			/* maximum time to live (seconds) */
#define	IPDEFTTL	64			/* default ttl, from RFC 1340 */
#define	IPFRAGTTL	60			/* time to live for frags, slowhz */
#define	IPTTLDEC	1			/* subtracted when forwarding */
#define	IP_MSS		576			/* default maximum segment size */
/*
 *  @(#)tcp.h 8.1 (Berkeley) 6/10/93
 */
typedef	u_int32_t	tcp_seq;

/*
 * TCP header.
 * Per RFC 793, September, 1981.
 */
struct tcphdr {
	u_int16_t	th_sport;		/* source port */
	u_int16_t	th_dport;		/* destination port */
	tcp_seq		th_seq;			/* sequence number */
	tcp_seq		th_ack;			/* acknowledgement number */
	u_int8_t	th_offx2;		/* data offset, rsvd */
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
	u_int8_t	th_flags;
#define	TH_FIN		0x01
#define	TH_SYN		0x02
#define	TH_RST		0x04
#define	TH_PUSH		0x08
#define	TH_ACK		0x10
#define	TH_URG		0x20
#define TH_ECNECHO	0x40		/* ECN Echo */
#define TH_CWR		0x80		/* ECN Cwnd Reduced */
	u_int16_t	th_win;			/* window */
	u_int16_t	th_sum;			/* checksum */
	u_int16_t	th_urp;			/* urgent pointer */
};

#define	TCPOPT_EOL			0
#define	TCPOPT_NOP			1
#define	TCPOPT_MAXSEG		2
#define TCPOLEN_MAXSEG		4
#define	TCPOPT_WSCALE		3	/* window scale factor (rfc1323) */
#define	TCPOPT_SACKOK		4	/* selective ack ok (rfc2018) */
#define	TCPOPT_SACK			5	/* selective ack (rfc2018) */
#define	TCPOPT_ECHO			6	/* echo (rfc1072) */
#define	TCPOPT_ECHOREPLY	7	/* echo (rfc1072) */
#define TCPOPT_TIMESTAMP	8	/* timestamp (rfc1323) */
#define TCPOLEN_TIMESTAMP	10
#define TCPOLEN_TSTAMP_APPA	(TCPOLEN_TIMESTAMP+2) /* appendix A */
#define TCPOPT_CC			11	/* T/TCP CC options (rfc1644) */
#define TCPOPT_CCNEW		12	/* T/TCP CC options (rfc1644) */
#define TCPOPT_CCECHO		13	/* T/TCP CC options (rfc1644) */
#define TCPOPT_TSTAMP_HDR	\
    (TCPOPT_NOP<<24|TCPOPT_NOP<<16|TCPOPT_TIMESTAMP<<8|TCPOLEN_TIMESTAMP)
	
/*
 * Key/Value hash table (hashtab) 
 */ 
#define HASHTAB_MAX_NODES	0xffffffff

struct hashtab_node {
	void *key;
	void *datum;
	struct hashtab_node *next;
};

struct hashtab {
	struct hashtab_node **htable;	/* hash table */
	u32 size;	/* number of slots in hash table */
	u32 nel;	/* number of elements in hash table */
	u32 (*hash_value)(struct hashtab *h, const void *key);
				/* hash function */
	int (*keycmp)(struct hashtab *h, const void *key1, const void *key2);
				/* key comparison function */
};

struct hashtab *hashtab_create(
	u32 (*hash_value)(struct hashtab *h, const void *key),
    int (*keycmp)(struct hashtab *h, const void *key1, const void *key2),
    u32 size)
{
	struct hashtab *p;
	u32 i;

	p = malloc(sizeof(*p));
	if (p == NULL)
		return p;

	p->size = size;
	p->nel = 0;
	p->hash_value = hash_value;
	p->keycmp = keycmp;
	p->htable = malloc(sizeof(*(p->htable)) * size);
	if (p->htable == NULL) {
		free(p);
		return NULL;
	}

	for (i = 0; i < size; i++)
		p->htable[i] = NULL;
	return p;
}

int hashtab_insert(struct hashtab *h, void *key, void *datum)
{
	u32 hvalue;
	struct hashtab_node *prev, *cur, *newnode;

	if (!h || h->nel == HASHTAB_MAX_NODES)
		return -1;

	hvalue = h->hash_value(h, key);
	prev = NULL;
	cur = h->htable[hvalue];
	while (cur && h->keycmp(h, key, cur->key) > 0) {
		prev = cur;
		cur = cur->next;
	}

	if (cur && (h->keycmp(h, key, cur->key) == 0))
		return -1;

	newnode = malloc(sizeof(*newnode));
	if (newnode == NULL)
		return -ENOMEM;
	newnode->key = key;
	newnode->datum = datum;
	if (prev) {
		newnode->next = prev->next;
		prev->next = newnode;
	} else {
		newnode->next = h->htable[hvalue];
		h->htable[hvalue] = newnode;
	}

	h->nel++;
	return 0;
}

void *hashtab_search(struct hashtab *h, const void *key)
{
	u32 hvalue;
	struct hashtab_node *cur;

	if (!h) return NULL;
	hvalue = h->hash_value(h, key);
	cur = h->htable[hvalue];
	while (cur != NULL && h->keycmp(h, key, cur->key) > 0)
		cur = cur->next;

	if (cur == NULL || (h->keycmp(h, key, cur->key) != 0))
		return NULL;

	return cur->datum;
}

void hashtab_destroy(struct hashtab *h)
{
	u32 i;
	struct hashtab_node *cur, *temp;

	if (!h) return;
	for (i = 0; i < h->size; i++) {
		cur = h->htable[i];
		while (cur != NULL) {
			temp = cur;
			cur = cur->next;
			free(temp);
		}
		h->htable[i] = NULL;
	}

	free(h->htable);
	h->htable = NULL;
	free(h);
}

u32 fnvhash(struct hashtab *h, const void *key)
{
	u32 hval = 0x811c9dc5;
	size_t len = 40;
    unsigned char *bp = (unsigned char *)key;
    unsigned char *be = bp + len;

	while (bp < be) {
		hval += (hval<<1) + (hval<<4) + (hval<<7) + (hval<<8) + (hval<<24);	
		hval ^= (u32)*bp++;
    }
	
    /* return our new hash value */
    return hval;
}

int fnvcmp(struct hashtab *h, const void *key1, const void *key2)
{
	return 0;
}

/*
 * Structure of vdaemon statistic structures.
 */
int get_ethx_info(char* devname,int prt);

struct cpu_info
{
    unsigned long long user;
    unsigned long long nice;
    unsigned long long system;
    unsigned long long idle;
    unsigned long long iowait;
    unsigned long long hardirq;
    unsigned long long softirq; 
    unsigned long long steal;
};

struct cpu_arch
{
    unsigned int procnum;
    char medel_name[512];
    unsigned int MHz;
    unsigned int freq;
	struct cpu_arch* next;
};

struct mem_info 
{
    unsigned long mem_total;
    unsigned long mem_free;
    unsigned long buffers;
    unsigned long cached;
    unsigned long swap_cached;
    unsigned long swap_total;
    unsigned long swap_free;
    unsigned long free_mem;     /*no proc*/
    unsigned long used_mem;     /*no proc*/
};

struct pid_stat
{
    unsigned int euid;
    unsigned int egid;
    unsigned int pid;
    char comm[PATH_MAX];
    char exe[PATH_MAX];
    char state;
    pid_t ppid;
    pid_t pgid;
    pid_t sid;
    int tty_nr;
    int tty_pgrp;
    unsigned int flags;
    unsigned long min_flt;
    unsigned long cmin_flt;
    unsigned long maj_flt;
    unsigned long cmaj_flt;
    unsigned long utime;
    unsigned long stimev;
    unsigned long cutime;
    unsigned long cstime;
    long priority;
    long nice;
    int num_threads;
    int zero;
    unsigned long long start_time;
    unsigned long vsize;
    unsigned long rss;
    unsigned long rlim;
    unsigned long start_code;
    unsigned long end_code;
    unsigned long start_stack;
    unsigned long esp;
    unsigned long eip;
    unsigned long pendingsig;
    unsigned long block_sig;
    unsigned long sigign;
    unsigned long sigcatch;
    unsigned long wchan;
    unsigned long nswap;
    unsigned long cnswap;
    int exit_signal;
    unsigned int task_cpu;
    unsigned int task_rt_priority;
    unsigned int task_policy;
    unsigned int rflags;
};

struct pid_io
{
    unsigned long long rchar;
    unsigned long long wchar;
    unsigned long long syscr;
    unsigned long long syscw;
    unsigned long long read_bytes;
    unsigned long long write_bytes;
    unsigned long long cancelled_write_bytes;
};

struct if_stats
{
    char devname[10];    
    unsigned long long rx_packets;
    unsigned long long tx_packets;
    unsigned long long rx_bytes;
    unsigned long long tx_bytes;
    unsigned long long rx_errors;
    unsigned long long tx_errors;
    unsigned long long rx_dropped;
    unsigned long long tx_dropped;
    unsigned long long rx_fifo;
    unsigned long long tx_fifo;
    unsigned long long rx_frame;
    unsigned long long tx_colls;
    unsigned long long rx_multicast;
    unsigned long long tx_carrier;
    unsigned long long rx_compressed;
    unsigned long long tx_compressed;
    unsigned int link;
    struct if_stats* next;
};

struct iface_dev 
{
    char name[16];
    struct in_addr ip;
    struct in_addr netmask;
    unsigned int link;
    struct iface_dev* next;
};

/* This should work for both 32 and 64 bit userland. */
struct ethtool_cmd 
{
    __u32	cmd;
    __u32	supported;	/* Features this interface supports */
    __u32	advertising;/* Features this interface advertises */
    __u16	speed;		/* The forced speed, 10Mb, 100Mb, gigabit */
    __u8	duplex;		/* Duplex, half or full */
    __u8	port;		/* Which connector port */
    __u8	phy_address;
    __u8	transceiver;/* Which transceiver to use */
    __u8	autoneg;	/* Enable or disable autonegotiation */
    __u32	maxtxpkt;	/* Tx pkts before generating tx int */
    __u32	maxrxpkt;	/* Rx pkts before generating rx int */
    __u32	reserved[4];
};

/* for passing single values */
struct ethtool_value 
{
    __u32	cmd;
    __u32	data;
};

union iaddr 
{
    unsigned u;
    unsigned char b[4];
};

struct fds_stat
{
    long fd_total;
    char* path_total;
    long db_ialloc;
    long sk_ialloc;
    long db_itotal;
    long sk_itotal;    
    long *db_inode;
    long *sk_inode;
    long long db_size;
    char *db_path;
};

struct conn_stat
{
    union iaddr laddr;
    union iaddr raddr;
    unsigned lport; 
    unsigned rport; 
    unsigned state; 
    unsigned txq; 
    unsigned rxq; 
    unsigned num;
    unsigned tr; 
    unsigned when; 
    unsigned retrnsmt; 
    unsigned uid;
    unsigned timeout;
    unsigned inode;
    struct conn_stat* next;
};

struct sock_stat
{
    unsigned int fe_port;
    unsigned int be_port;
    unsigned int fe_total;
    unsigned int be_total;
    struct conn_stat sk_stat;
};

struct disk_stat
{
    unsigned int major;
    unsigned int minor; 
    char *dev_name;
    unsigned long rd_ios;
    unsigned long rd_merges;
    unsigned long long rd_sectors;
    unsigned long rd_ticks;
    unsigned long wr_ios;
    unsigned long wr_merges;
    unsigned long long wr_sectors;
    unsigned long wr_ticks;
    unsigned long ios_pgr;
    unsigned long tot_ticks;
    unsigned long rq_ticks;
    struct disk_stat* next;
};

struct mounted_stat
{
    const char *device;
    const char *mount_point;
    const char *filesystem;
    const char *flags;
    struct mounted_stat* next;
};

struct tcp_stat
{
	//unsigned int ip;
	struct in_addr ip;
	unsigned short int port;
	unsigned short int dport;
    unsigned long long recv_bytes;
    unsigned long long sent_bytes;
    unsigned long long total_sent;
    unsigned long long total_recv;	
	
    unsigned long long pre_recv_bytes;
    unsigned long long pre_sent_bytes;
    unsigned long long pre_total_sent;
    unsigned long long pre_total_recv;	
	time_t start_time;
	struct tcp_stat* next;
};

struct vstate
{
    pid_t pid;
    double cpu_usage;
    double iow_usage;
    double mem_usage;
    struct cpu_arch st_arch;
    struct iface_dev st_ndev;
    struct cpu_info st_cpu;
    struct mem_info st_mem;
    struct pid_stat st_pid;
    struct pid_io st_pio;	
    struct if_stats st_ifs;
    struct fds_stat st_fds;
    struct sock_stat st_sock;
    struct disk_stat st_disk;
    struct mounted_stat st_mount;
	struct tcp_stat st_tcp;
	struct hashtab* htable;
};

int running = 1;    
int options = 0;
uid_t vsuid = 0;
pid_t vspid = 0;
int vsport = 0;
int intetval = 3;
char vsbuf[2046];
char head_line[1024];
char vsdev[10];
char *vsline = vsbuf;
struct vstate vst;
FILE* logfile = NULL;
char* app_name;

/* pcap descriptor */
pcap_t* pd = 0;
pcap_handler packet_handler;
struct hashtab *hashtable;
#define CAPTURE_LENGTH 72

/* ethernet address of interface. */
int have_hw_addr = 1;
unsigned char if_hw_addr[6];

/* IP address of interface */
int have_ip_addr = 0;
struct in_addr if_ip_addr;

/* ethernet address of gateway. */
int have_gw_addr = 1;
struct in_addr if_gw_addr;

int get_addrs_ioctl(char *interface, unsigned char* if_hw_addr, struct in_addr *if_ip_addr)
{
    struct ifreq ifr = {};
    int got_hw_addr = 0;
    int got_ip_addr = 0;

    int s = socket(PF_INET, SOCK_DGRAM, 0); /* any sort of IP socket will do */
    if (s == -1) {
        printf("create a socket error\n");
        return -1;
    }

    memset(if_hw_addr, 0, 6);
    strncpy(ifr.ifr_name, interface, IFNAMSIZ);

    if (ioctl(s, SIOCGIFHWADDR, &ifr) < 0) {
        printf( "Error getting hardware address for interface: %s\n", interface);         
    }
    else {
        memcpy(if_hw_addr, ifr.ifr_hwaddr.sa_data, 6);
        got_hw_addr = 1;
    }

    /* Get the IP address of the interface */
    (*(struct sockaddr_in *) &ifr.ifr_addr).sin_family = AF_INET;
    if (ioctl(s, SIOCGIFADDR, &ifr) < 0) {
        printf( "Unable to get IP address for interface: %s\n", interface); 
    }
    else {
        memcpy(if_ip_addr, &((*(struct sockaddr_in *) &ifr.ifr_addr).sin_addr), sizeof(struct in_addr));
        got_ip_addr = 2;
    }

    close(s);
    return got_hw_addr + got_ip_addr;
}

int get_gateway_addr(const char *dev)
{
    char ifname[64];
    in_addr_t dest, gway, mask;
    int flags, refcnt, use, metric, mtu, win, irtt;
    FILE *fp;
	if_gw_addr.s_addr = 0;
	
    fp = fopen("/proc/net/route", "r");
    if (fp == NULL)
        return -1;
		
    /* Skip the header line */
    if (fscanf(fp, "%*[^\n]\n") < 0) {
        fclose(fp);
        return -1;
    }
	
    while(1){
        int nread = fscanf(fp, "%63s%X%X%X%d%d%d%X%d%d%d\n",
                           ifname, &dest, &gway, &flags, &refcnt, &use, &metric, &mask,
                           &mtu, &win, &irtt);
        if (nread != 11)
            break;
        
		if(strcmp(ifname, dev) == 0 && gway){
			if_gw_addr.s_addr = gway;
			printf("%s gateway %s\n",dev,inet_ntoa(if_gw_addr));
			break;
		}              
    }
	
    fclose(fp);    
    return 0;
}



int ip_addr_match(struct in_addr addr) {
    return addr.s_addr == if_ip_addr.s_addr;
}

struct tcp_stat* get_tcp_stat(struct in_addr* ip,unsigned short int port,unsigned short int dport)
{
    struct tcp_stat *st_tcp = &vst.st_tcp;
	static struct tcp_stat *st_tcp_end = &vst.st_tcp;
	
    while (st_tcp){		
        if(st_tcp->ip.s_addr == ip->s_addr && st_tcp->port == port)
			return st_tcp;
        else
			st_tcp = st_tcp->next;
    }
	
	struct tcp_stat *st_new = 0;
	st_new = malloc(sizeof(struct tcp_stat));
	memset(st_new,0,sizeof(struct tcp_stat));		
	st_new->start_time = time(0);
	st_new->ip = *ip;
	st_new->port = port;
	st_new->dport =	dport;
	
	st_tcp_end->next = st_new;	
	st_tcp_end = st_new;
	return st_new;
}

inline struct tcp_stat* get_tcp_stat_head(struct in_addr* ip,unsigned short int port)
{
    struct tcp_stat *st_tcp = &vst.st_tcp;
	return st_tcp;
}

void calculate_tcp_rate(struct tcp_stat *tcp_stats)
{
	int row = 1;
	int nport1 = 0, nport2=0;
	double rx_bytes,tx_bytes;
	double rx_tbytes,tx_tbytes;
	double rx_port1 = 0,tx_port1 = 0;
	double rx_port2 = 0,tx_port2 = 0;
	double rx_tport1 = 0,tx_tport1 = 0;
	double rx_tport2 = 0,tx_tport2 = 0;
	
    struct tcp_stat *st_tcp = NULL;
	st_tcp = tcp_stats->next ? tcp_stats->next : NULL;
               	
	mvprintw(0,1,head_line);
	
    while (st_tcp){
		rx_bytes = st_tcp->recv_bytes - st_tcp->pre_recv_bytes;
		tx_bytes = st_tcp->sent_bytes - st_tcp->pre_sent_bytes;	
		
		rx_bytes /= (1024*intetval); 
		tx_bytes /= (1024*intetval);
				
		st_tcp->pre_recv_bytes = st_tcp->recv_bytes;
		st_tcp->pre_sent_bytes = st_tcp->sent_bytes;

		rx_tbytes = st_tcp->total_recv/1024; 
		tx_tbytes = st_tcp->total_sent/1024;
		time_t period = time(0) - st_tcp->start_time;			
		
		if(st_tcp->port == vsport+1 || st_tcp->dport == vsport+1){
			rx_port2 += rx_bytes;
			tx_port2 +=	tx_bytes;
			rx_tport2 += rx_tbytes;
			tx_tport2 += tx_tbytes;			
			nport2++;	
		}else{
			rx_port1 += rx_bytes;
			tx_port1 +=	tx_bytes;			
			rx_tport1 += rx_tbytes;
			tx_tport1 += tx_tbytes;
			nport1++;		
		}
		
		char c = ' ';
		if(st_tcp->port== vsport+1 || st_tcp->dport== vsport+1)
			c = 'B';
		else
			c = 'F';
			
		mvprintw(row,1,"%c %3d %15s :%5d %8.1fk %8.1fk %9.1fM %9.1fM %9.1fk %9.1fk",
			c,
			row,
			inet_ntoa(st_tcp->ip),st_tcp->port,
			rx_bytes,tx_bytes,rx_tbytes/1024,tx_tbytes/1024,
			rx_tbytes/period,tx_tbytes/period);
		row++;
		st_tcp = st_tcp->next;
    }
		
    //mvprintw(row++,1,"--------------------------------------------------------------------------------------------");	
	mvprintw(row++,1,"                                                                                            ");
	mvprintw(row++,1,"  ALL %15s :%5d %8.1fk %8.1fk %9.1fM %9.1fM","PORT  ", vsport, 
		rx_port1,tx_port1,rx_tport1/1024,tx_tport1/1024);
	
	mvprintw(row++,1,"  ALL %15s :%5d %8.1fk %8.1fk %9.1fM %9.1fM","PORT  ", vsport+1, 
		rx_port2,tx_port2,rx_tport2/1024,tx_tport2/1024);
	refresh();
}

void handle_ip_packet(struct ip* iptr, int hw_dir)
{
	int len;
	struct tcp_stat *st,*sa; 
	//unsigned int ip = 0;
	struct in_addr ip;
	unsigned short int port = 0;
	unsigned short int dport = 0;

	/* Does this protocol use ports? */
	if(iptr->ip_p != IPPROTO_TCP) 
		return;
	
	/* We take a slight liberty here by treating UDP the same as TCP */
	/* Find the TCP/UDP header */
	struct tcphdr* thdr = ((void*)iptr) + IP_HL(iptr) * 4;
	
	if(hw_dir == 0) {
		/* Packet incoming this interface. */
		ip = iptr->ip_src;
		port = ntohs(thdr->th_sport);
		dport= ntohs(thdr->th_dport);
		if(ip.s_addr == if_gw_addr.s_addr)
			return;				
	}
	else if(hw_dir == 1) {
		/* Packet leaving*/
		ip = iptr->ip_dst;
		port = ntohs(thdr->th_dport);
		dport= ntohs(thdr->th_sport);
		if(ip.s_addr == if_gw_addr.s_addr)
			return;		
	}
	
    /* Add the addresses to be resolved */
	st = get_tcp_stat(&ip,port,dport);
	sa = get_tcp_stat_head(&ip,port);
	
    len = ntohs(iptr->ip_len);
	if(st == NULL)
		return;
		
	//printf("%s:%d len %d\n",inet_ntoa(ip),port,len);
    /* Update record */
    if(hw_dir) {		
        st->sent_bytes += len;  /*leaving*/
        st->total_sent += len;
		sa->total_sent += len;		
    }
    else {		
        st->recv_bytes += len; /*entering*/
        st->total_recv += len;
		sa->total_recv += len;
    }
}

void handle_eth_packet(unsigned char* args, const struct pcap_pkthdr* pkthdr, const unsigned char* packet)
{
    struct ether_header *eptr;
    int ether_type;
    const unsigned char *payload;
    eptr = (struct ether_header*)packet;
    ether_type = ntohs(eptr->ether_type);
    payload = packet + sizeof(struct ether_header);

    if(ether_type == ETHERTYPE_IP) {
        struct ip* iptr;
        int dir = -1;
        
        /*
		* Is a direction implied by the MAC addresses?
		*/
        if(have_hw_addr && memcmp(eptr->ether_shost, if_hw_addr, 6) == 0 ) {
            /* packet leaving this i/f */
            dir = 1;
        }
        else if(have_hw_addr && memcmp(eptr->ether_dhost, if_hw_addr, 6) == 0 ) {
			/* packet entering this i/f */
			dir = 0;
		}
		else if (memcmp("\xFF\xFF\xFF\xFF\xFF\xFF", eptr->ether_dhost, 6) == 0) {
			/* broadcast packet, count as incoming */
            dir = 0;
		}

        iptr = (struct ip*)(payload); /* alignment? */
        handle_ip_packet(iptr, dir);
    }	
	else if (ether_type == ETHERTYPE_ARP)
	{
		/*printf ("Ethernet type hex:%x dec:%d is an ARP packet\n");*/
	}
	else{
		/*printf ("Ethernet type %x not IP\n");*/
	}	
}

/*
 * packet_init: performs pcap initialisation, called before ui is initialised
 */
int packet_init(char* dev) 
{
	int result = -1;
	int promisc = 0; /* set to promisc mode?*/
    char errbuf[PCAP_ERRBUF_SIZE];
    
	/* get network card interface*/
	have_hw_addr = 1;
	result = get_addrs_ioctl(dev, if_hw_addr, &if_ip_addr);
    if (result < 0)
		return -1;

	/* get interface gateway address*/
	result = get_gateway_addr(dev);
    if (result < 0)
		return -1;
	
	/* open interface with pcap*/
    pd = pcap_open_live(dev, CAPTURE_LENGTH, promisc, 1000, errbuf);
    if(pd == NULL) { 
        printf("pcap_open_live(%s): %s\n", dev, errbuf);
        return -1;
    }
	
	/* set callback handle function*/
	packet_handler = handle_eth_packet;
	
	sprintf(head_line,"%s %15s %5s %7s %7s %7s %7s %7s %7s\n",
              "# ###"," dstination ip","port"," recv(k/s)","sent(k/s)","recv total","sent total","in avg(k/s)","out avg(k/s)\n");
			  /*"# ###","dst ip       port - port","recv(k/s)","sent(k/s)","recv total","sent total","in avg(k/s)","out avg(k/s)\n");*/
	return 0;
}

int packet_filter(char* dev,int port)
{
	struct bpf_program* fp;	 		 /* The compiled filter expression */
	char filter_exp[20] = "port 13948";/* The filter expression */
	bpf_u_int32 mask;				 /* The netmask of our sniffing device */
	bpf_u_int32 net;				 /* The IP of our sniffing device */
	char errbuf[PCAP_ERRBUF_SIZE];
	
	/* get device ip/mask*/
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		 printf("Can't get netmask for device %s\n", dev);
		 net = 0;
		 mask = 0;
		 return -1;
	}
	
	/* compile filter exp*/
	sprintf(filter_exp,"portrange %d-%d",port,port+1);
	fp = malloc(sizeof(struct bpf_program));
	if (pcap_compile(pd, fp, filter_exp, 0, net) == -1) {
		printf("Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(pd));
		return -1;
	}

	/* set filter for port*/
	if (pcap_setfilter(pd, fp) == -1) {
		printf("Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(pd));
		return -1;
	}
	 
	return 0;
}

/* packet_loop:  * Worker function for packet capture thread. */
void* packet_loop(void* ptr) 
{
    /* loop pcap tcp/ip*/
    while(running) {
		pcap_loop(pd,-1,(pcap_handler)packet_handler,NULL);
	}
	return 0;
}

void print_usage()
{
	printf(" Options:\n");
	printf("  -d     indicate net device name\n");
    printf("  -p     indicate port\n");
	printf("  -v     print version\n");
	printf("  -h     printf help\n\n");
	printf("sample: -d \"eth0\" -p 8899\n\n");
}
	
int get_options(int argc,char **argv)
{
    int ret,opt = 0;
    /* read options */
    while((ret = getopt(argc, argv, "d:p:h")) >= 0) {
        switch(ret) {
        case 'd':
			strcpy(vsdev,optarg);
			opt++;
            break;				
        case 'p':
            vsport = atoi(optarg);
			opt++;
            break;								
        case 'h':
            print_usage();
            return -1;
        default:
            /* shouldn't happen */
            return -1;
        }
    }
	if(opt == 2)
		return 0;
    return ret;
}

void sig_handler(int sig)
{
    switch(sig) {
        case SIGHUP:
        case SIGTERM:
        case SIGINT:
        case SIGQUIT:
        case SIGUSR1:
        case SIGSEGV:
			running = 0;
			usleep(300000);
			if(pd != NULL)
			pcap_close(pd);			
            break;
        default:
            break;
    }
}

int main(int argc,char **argv) 
{        
    vsline = vsbuf;    
	running = 1;
	
    signal(SIGHUP,  sig_handler);
    signal(SIGTERM, sig_handler);
    signal(SIGINT,  sig_handler);
    signal(SIGQUIT, sig_handler);
    signal(SIGUSR1, sig_handler);
    signal(SIGSEGV, sig_handler);
	
    /* get vstat options*/
    if(get_options(argc,argv) != 0){
		printf("Type vpstat -h for help.\n");
        return 0;
	}
	
    /* init vst struct*/
    memset(&vst,0,sizeof(struct vstate));

	/* create ip+port hash table*/
	hashtable = hashtab_create(fnvhash, fnvcmp, 200);
	if (!hashtable)
		return -1;

	/* init pacp with device*/
	if(packet_init(vsdev) == -1)
		return -1;
	
	/* set filter for device*/
	if(packet_filter(vsdev,vsport) == -1)
		return -1;
	
	initscr();
	
    /* create pcap thread*/
    pthread_t tid;
    pthread_create(&tid,NULL,packet_loop,(void*)NULL);
	
	/* loop get pid stat*/
    while(running) {		
        /* print proc stat info*/
        usleep(1000000*intetval);
		calculate_tcp_rate(&vst.st_tcp);
    }

	endwin();    
    return EXIT_SUCCESS;
}
