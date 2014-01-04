#include "analyseur.h"

int main(int argc, char ** argv)
{
  checkIfSudo();
  int vFlag = 0;
  char *iFlag = NULL;
  char *oFlag = NULL;
  char *fFlag = NULL;
  int numberpacket = 10;

  getOptions(argc, argv, &vFlag, &iFlag, &oFlag, &fFlag);
  //printf("After getOptions\n");
  //int strcmpRes = strcmp(iFlag, "(null)");
  //printf("After strcmp\n");
  //printf("Strcmp of iFlag:%d",strcmpRes);

  char * errbuf = malloc(PCAP_ERRBUF_SIZE);
  pcap_t *handle = NULL;

  struct pcap_pkthdr header;/* The header that pcap gives us */
  const u_char *packet;/* The actual packet */

  /*if(!strcmp(iFlag,"(null)"))
  {*/
    openDevice(&iFlag, &handle, &errbuf);
    sniffPacket(&handle, &header, &packet);
    printPacket(packet, header.len);
    pcap_loop(handle, numberpacket, got_packet, NULL);
  /*}
  else
  {
    FILE * file = NULL;
    openFile(oFlag, &file);
  }*/

  /* And close the session */
  pcap_close(handle);
  return 0;
}

void getOptions(int argc, char ** argv, int * vFlag, char ** iFlag, char ** oFlag, char ** fFlag)
{
  if(argc < 2)
  {
    printHelp(argv);
  }
  int index;
  int c;
  // o v f i
  int optionsPresent[4] = {0,0,0,0};
  opterr = 0;

  while ((c = getopt (argc, argv, "i:o:v:f:")) != -1)
    switch (c)
    {
      case 'o':
        *oFlag = optarg;
        optionsPresent[0] = 1;
        break;
      case 'v':
        *vFlag = atoi(optarg);
        if( *vFlag < 1 || *vFlag > 3)
        {
          fprintf(stderr, "Option -v requires a value in [1,3].\n");
          exit(EXIT_FAILURE);
        }
        optionsPresent[1] = 1;
        break;
      case 'f':
        *fFlag = optarg;
        optionsPresent[2] = 1;
        break;
      case 'i':
        *iFlag = optarg;
        optionsPresent[3] = 1;
        break;
      case '?':
        if (optopt == 'v'
          || optopt == 'f'
          || optopt == 'i'
          || optopt == 'o')
          fprintf (stderr, "Option -%c requires an argument.\n", optopt);
        else if (isprint (optopt))
          fprintf (stderr, "Unknown option `-%c'.\n", optopt);
        else
          fprintf (stderr,"Unknown option character `\\x%x'.\n",optopt);
          exit(EXIT_FAILURE);
      default:
        abort ();
    }

    printf ("vFlag = %d, iFlag = %s, fFlag = %s, oFlag = %s\n",*vFlag, *iFlag, *fFlag, *oFlag);

    for (index = optind; index < argc; index++)
      fprintf (stderr,"Non-option argument %s\n", argv[index]);

    if(optionsPresent[0] && optionsPresent[3])
    {
      fprintf(stderr, "Options -i and -o cannot be present at the same time.\n");
      exit(EXIT_FAILURE);
    }
    if( ! optionsPresent[0] && !optionsPresent[3])
    {
      fprintf(stderr,"Options -o or -i must be present.\n");
      exit(EXIT_FAILURE);
    }
    if( ! optionsPresent[1])
    {
      fprintf(stderr,"Option -v not present.\n");
      exit(EXIT_FAILURE);
    }
    printf("End of getOptions\n");
}

void printHelp(char ** argv)
{
    printf("Usage: %s [-f filter] -i interface -o file -v verbosity\n",argv[0]);
    printf("  where -o and -i are mandatory and exclusive,\n");
    printf("        -f is not mandatory,\n");
    printf("        -v is mandatory and is an integer in [1,3] with 1 being low verbosity and 3 high verbosity.\n");
    exit(EXIT_SUCCESS);
}

void checkIfSudo()
{
  if(getuid() != 0)
  {
    printf("Please run as root.\n");
    exit(EXIT_FAILURE);
  }
}

void openDevice(char ** device, pcap_t ** handle, char ** errbuf)
{
  struct bpf_program fp;
  char filter_exp[] = "port 80";
  //bpf_u_int32 mask = 0;  /* The netmask of our sniffing device */
  bpf_u_int32 net = 0;  /* The IP of our sniffing device */
  printf("Opening device %s...\n", *device);

  *handle = pcap_open_live(*device, BUFSIZ, 1, 1000, *errbuf); //Start sniffing
  if (*handle == NULL)
  {
    fprintf(stderr, "Couldn't open device %s: %s\n", *device, *errbuf);
    exit(EXIT_FAILURE);
 }
  if (pcap_datalink(*handle) != DLT_EN10MB) { //Indicates the type of link layer headers
  fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", *device);
    //fails if the device doesn't supply Ethernet headers
    exit(EXIT_FAILURE);
 }
  printf("Device %s opened succesfully\n", *device);
  if (pcap_compile(*handle, &fp, filter_exp, 0, net) == -1) {
    fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(*handle));
    exit(EXIT_FAILURE);
   }
}

void sniffPacket(pcap_t ** handle,struct pcap_pkthdr *  header, const u_char **packet)
{
  *packet = pcap_next(*handle, header);
  /* Print its length */
 printf("Jacked packet with length of [%d]\n", header->len);
}

void printPacket(const u_char * packet, int length)
{
  int i = 0;
  for(i=0; i < length; i++)
  {
    if(i%16==15)
    {
      printf("%02x\n",(packet[i]));
    }
    printf("%x ", packet[i]);
  }
  printf("\n");
}

/*void printascii(const u_char *trame, int len)
{

        int len_rem = len;
        int line_width = 16;
        int line_len;
        int offset = 0;
        const u_char *ch = trame;

        if (len <= 0)
                return;

        if (len <= line_width) {
                printHexPacket(ch, len, offset);
                return;
        }
                printHexPacket(ch, line_len, offset);
                len_rem = len_rem - line_len;
                ch = ch + line_len;
                offset = offset + line_width;

                if (len_rem <= line_width) {
                        printHexPacket(ch, len_rem, offset);

                }
  return;
}*/
void printAscii(u_char *packet, int length){
    int i;
    int rank =0;
    for(i=0;i< length;i++, rank++){
        if(isprint(packet[i])){        
            printf("%c", (packet[i]));
        }
        else if(packet[i] == '\n'){        
            printf("%c", (packet[i]));
            rank=0;
        }
        else if(packet[i] == '\r'){        
        //printf("%c", (packet[i]));
            rank=0;
        }
        else
            printf(".");
        if(rank%64==63)
            printf("\n");
    }
    printf("\n");

};

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
  const struct sniff_ethernet *ethernet;
  const struct sniff_ip *ip;
  const struct sniff_tcp *tcp;
  const struct sniff_udp *udp;
  const struct sniff_arp *arp;
  const struct bootp *bootp;
  u_char* trame;
  int size_ethernet = sizeof(struct sniff_ethernet);
  int size_ip;
  int size_tcp;
  int size_trame;
  int *vFlag = (int *) args;

  ethernet = (struct sniff_ethernet*)(packet);
  ip = (struct sniff_ip*)(packet+size_ethernet);
  size_ip=IP_HL(ip)*4;
  tcp = (struct sniff_tcp*)(packet+size_ip+size_ethernet);
  size_tcp=TH_OFF(tcp)*4;
  udp = (struct sniff_udp*)(packet+SIZE_UDP+size_ethernet);
  arp = (struct sniff_arp *)(packet+14);
  bootp = (struct bootp *)(packet);
  printArp(*arp);
  printf("TRACE: \n");
  printEther(ethernet,*vFlag);

  char *aux = inet_ntoa(ip->ip_src);
  char *ab = strcpy(malloc(strlen(aux)+1), aux);
  char *bux = inet_ntoa(ip->ip_dst);
  char *cd = strcpy(malloc(strlen(aux)+1), bux);
  printf("Type de service : %d\n", ip->ip_tos);
  printf("From IP: %s\nTo: %s\n",ab,cd);
  printf("Version = %d\n", ip->ip_vhl);
  printf("Length = %d\n", ip->ip_len);

  //Switch sur type protocol
  switch(ip->ip_p)
  {
    case IPPROTO_TCP:
      printf("Protocol TCP\n");
      printf("Source Port = %d\n" ,ntohs(tcp->th_sport));
      printf("Destination Port = %d\n", ntohs(tcp->th_dport));
      printf("Data Offset = %d\n", ntohs(tcp->th_offx2));
      printf("Window = %d\n", ntohs(tcp->th_win));
      printf("\n");
      break;
    case IPPROTO_UDP:
      printf("Protocol UDP\n");
      printf("Source Port = %d\nDestination Port = %d\n", ntohs(udp->uh_sport), ntohs(udp->uh_dport));
      printf("\n");
      break;
    default:
      printf("Unknown Protocol\n");
      break;
  }

        trame = (u_char *)(packet + size_ethernet + size_ip + size_tcp);
        size_trame = ntohs(ip->ip_len) - (size_ip + size_tcp);
        if (size_trame > 0) {
                printf("DATA (%d bytes):\n", size_trame);
                printAscii(trame, size_trame);
        }
  printBootp(bootp, *vFlag);
  return;
}

void printEther(const struct sniff_ethernet* ethernet, int verbosite)
{
  printf("**********ETHERNET**********");
  if(verbosite > 1)
  {
    printf("Destination host address : ");
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
    ((unsigned)ethernet->ether_dhost[0]),//ntohs sur la globalité
    ((unsigned)ethernet->ether_dhost[1]),
    ((unsigned)ethernet->ether_dhost[2]),
    ((unsigned)ethernet->ether_dhost[3]),
    ((unsigned)ethernet->ether_dhost[4]),
    ((unsigned)ethernet->ether_dhost[5]));
    printf("Source host address : ");
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
    ((unsigned)ethernet->ether_shost[0]),
    ((unsigned)ethernet->ether_shost[1]),
    ((unsigned)ethernet->ether_shost[2]),
    ((unsigned)ethernet->ether_shost[3]),
    ((unsigned)ethernet->ether_shost[4]),
    ((unsigned)ethernet->ether_shost[5]));
    if(verbosite > 2)
    {
      printf("Ether_type : [%i]\n", ethernet->ether_type);
    }
  }
}

void printArp(struct sniff_arp arp)
{
  printf("**********ARP**********\n");
  printf("Hardware type : %u (%s) \n", ntohs(arp.htype),(ntohs(arp.htype) == 1) ? "Ethernet" : "Inconnu");
  printf("Protocol : %u (%s) \n", arp.ptype,(ntohs(arp.ptype) == ETHERTYPE_IP) ? "IPv4" : "Inconnu");
}

void printBootp(const struct bootp* bp, int verbosite)
{
   printf("**********BOOTP**********\n");
   printf("Operation : %d ",bp->bp_op);
   if(bp->bp_op == BOOTREQUEST)
   printf("(REQUEST)\n");
   if(bp->bp_op == BOOTREPLY)
         printf("(RESPONSE)\n");
   if(verbosite>3){
     printf("Hardware address type: %d\n",bp->bp_htype);
     printf("Hardware address length: %d\n",bp->bp_hlen);
     printf("Jump number : %d\n",bp->bp_hops);
     printf("Transaction ID: %u\n",ntohl(bp->bp_xid));
     printf("Boot time in sec : %d\n",ntohs(bp->bp_secs));
     }
     printf("Client IP: %s\n", inet_ntoa(bp->bp_ciaddr));
     printf("Your IP: %s\n", inet_ntoa(bp->bp_yiaddr));
     printf("Server IP: %s\n", inet_ntoa(bp->bp_siaddr));
     printf("Passerelle IP: %s\n", inet_ntoa(bp->bp_giaddr));
     int i;
     printf("MAC client address: %02x",bp->bp_chaddr[0]);
     for(i=1;i<bp->bp_hlen;i++)
         printf(":%02x",bp->bp_chaddr[i]);
     printf("\n");
     printf("Server name: %s\n", bp->bp_sname);
     if(verbosite>3)
         printf("Boot file: %s\n", bp->bp_file);
     if( bp->bp_vend[0] == 99 && bp->bp_vend[1] == 130 && bp->bp_vend[2] == 83 && bp->bp_vend[3] == 99 ){
         printf("MAGIC COOKIE DETECTED\n");
     printf("Options : ");
     i = 4;
     while(bp->bp_vend[i]!=0xFF){
         switch(bp->bp_vend[i]){
             case TAG_DHCP_MESSAGE:
             switch(bp->bp_vend[i+2]){
                 case DHCPDISCOVER:
                 printf("DHCP DISCOVER\n");
                 break;
                 case DHCPOFFER:
                 printf("DHCP OFFER\n");
                 break;
                 case DHCPDECLINE:
                 printf("DHCP DECLINE\n");
                 break;
                 case DHCPACK:
                 printf("DHCP ACK\n");
                 break;
                 case DHCPNAK:
                 printf("DHCP NACK\n");
                 break;
                 case DHCPRELEASE:
                 printf("DHCP RELEASE\n");
                 break;
                 default:
                 break;
             }
             break;
             case TAG_CLIENT_ID:
             printf("Hardware type : %d (%s)\n",bp->bp_vend[i+2],(bp->bp_vend[i+2] == 1) ? "Ethernet" : "Inconnu");
             int j =i+3;
             printf("Hardware ethernet address: %02x",bp->bp_vend[j]);
             for(j++;j<bp->bp_vend[i+1]+i+2;j++)
                printf(":%02x",bp->bp_vend[j]);
             printf("\n");
             break;
             case TAG_HOSTNAME:
             printf("Device name: ");
             printAscii((u_char *) &bp->bp_vend[i+2],bp->bp_vend[i+1]-1);
             break;
             case TAG_PARM_REQUEST:
             printf("Parameters:\n");
             j =i+3;
             for(;j<bp->bp_vend[i+1]+i+2;j++)
                 switch(bp->bp_vend[j]){
                     case TAG_GATEWAY:
                     printf("ROUTER ");
                     break;
                     case TAG_DOMAIN_SERVER:
                     printf("DNS ");
                     break;
                     case TAG_DOMAINNAME:
                     printf("DOMAIN_NAME ");
                     break;
                     case TAG_BROAD_ADDR:
                     printf("BROADCAST_ADDRESS ");
                     break;
                     case TAG_SUBNET_MASK:
                     printf("SUBNET_MASK ");
                     break;
                     case TAG_TIME_OFFSET:
                     printf("TIME_OFFSET ");
                     break;
                     case TAG_HOSTNAME:
                     printf("HOST_NAME ");
                     break;
                     case TAG_NETBIOS_NS:
                     printf("NETBIOS_OVER_TCP/IP_NAME_SERVER ");
                     break;
                     case TAG_NETBIOS_SCOPE:
                     printf("NETBIOS_OVER_TCP/IP_SCOPE ");
                     break;
                     case TAG_REQUESTED_IP:
                     printf("REQUESTED_IP_ADDRESS ");
                     break;
                     case TAG_IP_LEASE:
                     printf("LEASE_TIME ");
                     break;
                     case TAG_SERVER_ID:
                     printf("SERVER_ID ");
                     break;
                     case TAG_PARM_REQUEST:
                     printf("PARAMETER_REQUEST_LIST ");
                     break;
                     default:
                     printf("UNKNOWN ");
                     break;
                 }
                 printf("\n");
                 break;
                 case TAG_GATEWAY:
                 j =i+3;
                 printf("Router address: %d",bp->bp_vend[j]);
                 for(j++;j<bp->bp_vend[i+1]+i+3;j++)
                     printf(".%d",bp->bp_vend[j]);
                 printf("\n");
                 break;
                 case TAG_DOMAIN_SERVER:
                 j =i+3;
                 printf("DNS Server IP address: %d",bp->bp_vend[j]);
                 for(j++;j<bp->bp_vend[i+1]+i+3;j++)
                     printf(".%d",bp->bp_vend[j]);
                 printf("\n");
                 break;
                 case TAG_DOMAINNAME:
                 printf("Domain name: ");
                 printAscii((u_char *) &bp->bp_vend[i+2],bp->bp_vend[i+1]-1);
                 break;
                 case TAG_BROAD_ADDR:
                 j =i+3;
                 printf("Broadcast IP address: %d",bp->bp_vend[j]);
                 for(j++;j<bp->bp_vend[i+1]+i+3;j++)
                     printf(".%d",bp->bp_vend[j]);
                 printf("\n");
                 break;
                 case TAG_SUBNET_MASK:
                 j =i+3;
                 printf("Subnet mask: %d",bp->bp_vend[j]);
                 for(j++;j<bp->bp_vend[i+1]+i+3;j++)
                     printf(".%d",bp->bp_vend[j]);
                 printf("\n");
                 break;
                 /*case TAG_TIME_OFFSET:
                 printf("TIME_OFFSET \n");//Non capturer
                 printf("Decalage : %u s\n",bp->bp_vend[i+2]*256*256*256+bp->bp_vend[i+3]*256*256+bp->bp_vend[i+4]*256+bp->bp_vend[i+5]);
                 break;*/
                 case TAG_NETBIOS_NS:
                 j =i+3;
                 printf("Name server IP address: %d",bp->bp_vend[j]);
                 for(j++;j<bp->bp_vend[i+1]+i+3;j++)
                     printf(".%d",bp->bp_vend[j]);
                 printf("\n");
                 break;
                 /*case TAG_NETBIOS_SCOPE://Non capturer
                 j =i+3;
                 printf("NETBIOS_OVER_TCP/IP_SCOPE : %d",bp->bp_vend[j]);
                 for(j++;j<bp->bp_vend[i+1]+i+3;j++)
                     printf(".%d",bp->bp_vend[j]);
                 printf("\n");
                 break;*/
                 case TAG_REQUESTED_IP:
                 j =i+3;
                 printf("Asked IP address: %d",bp->bp_vend[j]);
                 for(j++;j<bp->bp_vend[i+1]+i+3;j++)
                     printf(".%d",bp->bp_vend[j]);
                 printf("\n");
                 break;
                 case TAG_IP_LEASE:
                 printf("Lease time: %u s\n",bp->bp_vend[i+2]*256*256*256+bp->bp_vend[i+3]*256*256+bp->bp_vend[i+4]*256+bp->bp_vend[i+5]);
                 break;
                 case TAG_SERVER_ID:
                 j =i+3;
                 printf("Server IP address: %d",bp->bp_vend[j]);
                 for(j++;j<bp->bp_vend[i+1]+i+3;j++)
                     printf(".%d",bp->bp_vend[j]);
                 printf("\n");
                break;
                default:
                printf("Not an option: %d\n",bp->bp_vend[i]);
                break;
             }
              i+=2+bp->bp_vend[i+1];
         }
      }
        if(verbosite>2)
        printPacket((u_char *) bp, sizeof(struct bootp));

};

void openFile(char * name, FILE ** file)
{
    *file = fopen(name, "r");
    if(*file == NULL)
    {
      fprintf(stderr,"File %s could not be opened.\n", name);
      exit(EXIT_FAILURE);
    }
    else
    {
      printf("File %s opened succesfully.\n",name);
    }

}

