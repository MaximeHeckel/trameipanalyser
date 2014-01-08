#ifndef ANALYSEUR_H
#define ANALYSEUR_H
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <arpa/telnet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <arpa/telnet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/if_arp.h>
#include "bootp.h"

/* Ethernet addresses are 6 bytes */
//#define ETHER_ADDR_LEN  6
#define SIZE_UDP        8
#define ARP_REQUEST 1   /* ARP Request             */
#define ARP_REPLY 2     /* ARP Reply               */
#define IP_HL(ip)                (((ip)->ip_hl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_hl) >> 4)
#define TH_OFF(th)        (((th)->th_off & 0xf0) >> 4)

#endif
#define DNS_A 1
#define DNS_NS 2
#define DNS_CNAME 5
#define DNS_SOA 6
#define DNS_MX 15
#define DNS_AAAA 28

#define DNS_IN 1
#define DNS_ANY 255

struct dns_header{
  unsigned short id;
  unsigned short flags;
  unsigned short qd;
  unsigned short an;
  unsigned short ns;
  unsigned short ar;
};

struct dns_answer{
  unsigned short name;
  unsigned short type;
  unsigned short classe;
  unsigned short _ttl;
  unsigned short ttl;
  unsigned short length;
};
void getOptions(int argc, char ** argv, int * vFlag, char ** iFlag, char ** oFlag, char ** fFlag);
void checkIfSudo();
void ctrl_c(int n);
void openDevice(char ** device,pcap_t ** handle, char ** errbuf);
void printHelp(char ** argv);
void printPacket(const u_char * packet, int length);
void print_payload(const u_char *trame, int len);
void printEther(const struct ether_header* ethernet, int verbosite);
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void printIP(const struct ip* ip, int verbosite);
void openFile(char * name, FILE ** file);
void printTcp(const struct tcphdr* tcp, int verbosite);
void printUdp(const struct udphdr* udp, int verbosite);
void printArp(struct arphdr* arp, int verbosite);
void printBootp(const struct bootp* bp, int verbosite);
void printDns(u_char *data, int verbosite, int type);
void openOfflineDevice(char * name, pcap_t ** handle, char ** errbuf);
void applyFilter(pcap_t ** handle,char * filter, struct bpf_program * fp, bpf_u_int32 * net);
