/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 * 
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */
/*
 * Bootstrap Protocol (BOOTP).  RFC 951.
 */
/*
 * HISTORY
 *
 * 14 May 1992 ? at NeXT
 *	Added correct padding to struct nextvend.  This is
 *	needed for the i386 due to alignment differences wrt
 *	the m68k.  Also adjusted the size of the array fields
 *	because the NeXT vendor area was overflowing the bootp
 *	packet.
 */

#include <netinet/udp.h>

#define iaddr_t struct in_addr
#define TAG_PAD                        ((unsigned char)   0)
#define TAG_SUBNET_MASK                ((unsigned char)   1)
#define TAG_TIME_OFFSET                ((unsigned char)   2)
#define TAG_GATEWAY                ((unsigned char)   3)
#define TAG_TIME_SERVER                ((unsigned char)   4)
#define TAG_NAME_SERVER                ((unsigned char)   5)
#define TAG_DOMAIN_SERVER        ((unsigned char)   6)
#define TAG_LOG_SERVER                ((unsigned char)   7)
#define TAG_COOKIE_SERVER        ((unsigned char)   8)
#define TAG_LPR_SERVER                ((unsigned char)   9)
#define TAG_IMPRESS_SERVER        ((unsigned char)  10)
#define TAG_RLP_SERVER                ((unsigned char)  11)
#define TAG_HOSTNAME                ((unsigned char)  12)
#define TAG_BOOTSIZE                ((unsigned char)  13)
#define TAG_END                        ((unsigned char) 255)
/* RFC1497 tags */
#define        TAG_DUMPPATH                ((u_int8_t)  14)
#define        TAG_DOMAINNAME                ((u_int8_t)  15)
#define        TAG_SWAP_SERVER                ((u_int8_t)  16)
#define        TAG_ROOTPATH                ((u_int8_t)  17)
#define        TAG_EXTPATH                ((u_int8_t)  18)
/* RFC2132 */
#define        TAG_IP_FORWARD                ((u_int8_t)  19)
#define        TAG_NL_SRCRT                ((u_int8_t)  20)
#define        TAG_PFILTERS                ((u_int8_t)  21)
#define        TAG_REASS_SIZE                ((u_int8_t)  22)
#define        TAG_DEF_TTL                ((u_int8_t)  23)
#define        TAG_MTU_TIMEOUT                ((u_int8_t)  24)
#define        TAG_MTU_TABLE                ((u_int8_t)  25)
#define        TAG_INT_MTU                ((u_int8_t)  26)
#define        TAG_LOCAL_SUBNETS        ((u_int8_t)  27)
#define        TAG_BROAD_ADDR                ((u_int8_t)  28)
#define        TAG_DO_MASK_DISC        ((u_int8_t)  29)
#define        TAG_SUPPLY_MASK                ((u_int8_t)  30)
#define        TAG_DO_RDISC                ((u_int8_t)  31)
#define        TAG_RTR_SOL_ADDR        ((u_int8_t)  32)
#define        TAG_STATIC_ROUTE        ((u_int8_t)  33)
#define        TAG_USE_TRAILERS        ((u_int8_t)  34)
#define        TAG_ARP_TIMEOUT                ((u_int8_t)  35)
#define        TAG_ETH_ENCAP                ((u_int8_t)  36)
#define        TAG_TCP_TTL                ((u_int8_t)  37)
#define        TAG_TCP_KEEPALIVE        ((u_int8_t)  38)
#define        TAG_KEEPALIVE_GO        ((u_int8_t)  39)
#define        TAG_NIS_DOMAIN                ((u_int8_t)  40)
#define        TAG_NIS_SERVERS                ((u_int8_t)  41)
#define        TAG_NTP_SERVERS                ((u_int8_t)  42)
#define        TAG_VENDOR_OPTS                ((u_int8_t)  43)
#define        TAG_NETBIOS_NS                ((u_int8_t)  44)
#define        TAG_NETBIOS_DDS                ((u_int8_t)  45)
#define        TAG_NETBIOS_NODE        ((u_int8_t)  46)
#define        TAG_NETBIOS_SCOPE        ((u_int8_t)  47)
#define        TAG_XWIN_FS                ((u_int8_t)  48)
#define        TAG_XWIN_DM                ((u_int8_t)  49)
#define        TAG_NIS_P_DOMAIN        ((u_int8_t)  64)
#define        TAG_NIS_P_SERVERS        ((u_int8_t)  65)
#define        TAG_MOBILE_HOME                ((u_int8_t)  68)
#define        TAG_SMPT_SERVER                ((u_int8_t)  69)
#define        TAG_POP3_SERVER                ((u_int8_t)  70)
#define        TAG_NNTP_SERVER                ((u_int8_t)  71)
#define        TAG_WWW_SERVER                ((u_int8_t)  72)
#define        TAG_FINGER_SERVER        ((u_int8_t)  73)
#define        TAG_IRC_SERVER                ((u_int8_t)  74)
#define        TAG_STREETTALK_SRVR        ((u_int8_t)  75)
#define        TAG_STREETTALK_STDA        ((u_int8_t)  76)
/* DHCP options */
#define        TAG_REQUESTED_IP        ((u_int8_t)  50)
#define        TAG_IP_LEASE                ((u_int8_t)  51)
#define        TAG_OPT_OVERLOAD        ((u_int8_t)  52)
#define        TAG_TFTP_SERVER                ((u_int8_t)  66)
#define        TAG_BOOTFILENAME        ((u_int8_t)  67)
#define        TAG_DHCP_MESSAGE        ((u_int8_t)  53)
#define        TAG_SERVER_ID                ((u_int8_t)  54)
#define        TAG_PARM_REQUEST        ((u_int8_t)  55)
#define        TAG_MESSAGE                ((u_int8_t)  56)
#define        TAG_MAX_MSG_SIZE        ((u_int8_t)  57)
#define        TAG_RENEWAL_TIME        ((u_int8_t)  58)
#define        TAG_REBIND_TIME                ((u_int8_t)  59)
#define        TAG_VENDOR_CLASS        ((u_int8_t)  60)
#define        TAG_CLIENT_ID                ((u_int8_t)  61)
/* RFC 2241 */
#define        TAG_NDS_SERVERS                ((u_int8_t)  85)
#define        TAG_NDS_TREE_NAME        ((u_int8_t)  86)
#define        TAG_NDS_CONTEXT                ((u_int8_t)  87)
/* RFC 2242 */
#define        TAG_NDS_IPDOMAIN        ((u_int8_t)  62)
#define        TAG_NDS_IPINFO                ((u_int8_t)  63)
/* RFC 2485 */
#define        TAG_OPEN_GROUP_UAP        ((u_int8_t)  98)
/* RFC 2563 */
#define        TAG_DISABLE_AUTOCONF        ((u_int8_t) 116)
/* RFC 2610 */
#define        TAG_SLP_DA                ((u_int8_t)  78)
#define        TAG_SLP_SCOPE                ((u_int8_t)  79)
/* RFC 2937 */
#define        TAG_NS_SEARCH                ((u_int8_t) 117)
/* RFC 3011 */
#define        TAG_IP4_SUBNET_SELECT        ((u_int8_t) 118)
/* ftp://ftp.isi.edu/.../assignments/bootp-dhcp-extensions */
#define        TAG_USER_CLASS                ((u_int8_t)  77)
#define        TAG_SLP_NAMING_AUTH        ((u_int8_t)  80)
#define        TAG_CLIENT_FQDN                ((u_int8_t)  81)
#define        TAG_AGENT_CIRCUIT        ((u_int8_t)  82)
#define        TAG_AGENT_REMOTE        ((u_int8_t)  83)
#define        TAG_AGENT_MASK                ((u_int8_t)  84)
#define        TAG_TZ_STRING                ((u_int8_t)  88)
#define        TAG_FQDN_OPTION                ((u_int8_t)  89)
#define        TAG_AUTH                ((u_int8_t)  90)
#define        TAG_VINES_SERVERS        ((u_int8_t)  91)
#define        TAG_SERVER_RANK                ((u_int8_t)  92)
#define        TAG_CLIENT_ARCH                ((u_int8_t)  93)
#define        TAG_CLIENT_NDI                ((u_int8_t)  94)
#define        TAG_CLIENT_GUID                ((u_int8_t)  97)
#define        TAG_LDAP_URL                ((u_int8_t)  95)
#define        TAG_6OVER4                ((u_int8_t)  96)
#define        TAG_PRINTER_NAME        ((u_int8_t) 100)
#define        TAG_MDHCP_SERVER        ((u_int8_t) 101)
#define        TAG_IPX_COMPAT                ((u_int8_t) 110)
#define        TAG_NETINFO_PARENT        ((u_int8_t) 112)
#define        TAG_NETINFO_PARENT_TAG        ((u_int8_t) 113)
#define        TAG_URL                        ((u_int8_t) 114)
#define        TAG_FAILOVER                ((u_int8_t) 115)
#define        TAG_EXTENDED_REQUEST        ((u_int8_t) 126)
#define        TAG_EXTENDED_OPTION        ((u_int8_t) 127)


/* DHCP Message types (values for TAG_DHCP_MESSAGE option) */
#define                DHCPDISCOVER        1
#define                DHCPOFFER        2
#define                DHCPREQUEST        3
#define                DHCPDECLINE        4
#define                DHCPACK                5
#define                DHCPNAK                6
#define                DHCPRELEASE        7
#define                DHCPINFORM        8

struct bootp {
	u_char	bp_op;		/* packet opcode type */
#define	BOOTREQUEST	1
#define	BOOTREPLY	2
	u_char	bp_htype;	/* hardware addr type */
	u_char	bp_hlen;	/* hardware addr length */
	u_char	bp_hops;	/* gateway hops */
	u_int32_t bp_xid;	/* transaction ID */
	u_short	bp_secs;	/* seconds since boot began */	
	u_short	bp_unused;
	iaddr_t	bp_ciaddr;	/* client IP address */
	iaddr_t	bp_yiaddr;	/* 'your' IP address */
	iaddr_t	bp_siaddr;	/* server IP address */
	iaddr_t	bp_giaddr;	/* gateway IP address */
	u_char	bp_chaddr[16];	/* client hardware address */
	u_char	bp_sname[64];	/* server host name */
	u_char	bp_file[128];	/* boot file name */
	u_char	bp_vend[64];	/* vendor-specific area */
};

/*
 * UDP port numbers, server and client.
 */
#define	IPPORT_BOOTPS		67
#define	IPPORT_BOOTPC		68

/*
 * "vendor" data permitted for Stanford boot clients.
 */
struct vend {
	u_char	v_magic[4];	/* magic number */
	u_int32_t v_flags;	/* flags/opcodes, etc. */
	u_char	v_unused[56];	/* currently unused */
};
#define	VM_STANFORD	"STAN"	/* v_magic for Stanford */

/* v_flags values */
#define	VF_PCBOOT	1	/* an IBMPC or Mac wants environment info */
#define	VF_HELP		2	/* help me, I'm not registered */

#define	NVMAXTEXT	55	/* don't change this, it just fits RFC951 */
struct nextvend {
	u_char nv_magic[4];	/* Magic number for vendor specificity */
	u_char nv_version;	/* NeXT protocol version */
	/*
	 * Round the beginning
	 * of the union to a 16
	 * bit boundary due to
	 * struct/union alignment
	 * on the m68k.
	 */
	unsigned short	:0;	
	union {
		u_char NV0[58];
		struct {
			u_char NV1_opcode;	/* opcode - Version 1 */
			u_char NV1_xid;	/* transcation id */
			u_char NV1_text[NVMAXTEXT];	/* text */
			u_char NV1_null;	/* null terminator */
		} NV1;
	} nv_U;
};
#define	nv_unused	nv_U.NV0
#define	nv_opcode	nv_U.NV1.NV1_opcode
#define	nv_xid		nv_U.NV1.NV1_xid
#define	nv_text		nv_U.NV1.NV1_text
#define nv_null		nv_U.NV1.NV1_null

/* Magic number */
#define VM_NEXT		"NeXT"	/* v_magic for NeXT, Inc. */

/* Opcodes */
#define	BPOP_OK		0
#define BPOP_QUERY	1
#define	BPOP_QUERY_NE	2
#define	BPOP_ERROR	3

struct bootp_packet {
    struct ip bp_ip;
    struct udphdr bp_udp;
    struct bootp bp_bootp;
};

#define	BOOTP_PKTSIZE (sizeof (struct bootp_packet))

/* backoffs must be masks */
#define	BOOTP_MIN_BACKOFF	0x7ff		/* 2.048 sec */
#define	BOOTP_MAX_BACKOFF	0xffff		/* 65.535 sec */
#define	BOOTP_RETRY		6		/* # retries */

