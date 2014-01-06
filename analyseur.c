#include "analyseur.h"

int main(int argc, char ** argv)
{
  checkIfSudo();
  int vFlag = 0;
  char *iFlag = NULL;
  char *oFlag = NULL;
  char *fFlag = "port 80";

  getOptions(argc, argv, &vFlag, &iFlag, &oFlag, &fFlag);
  char * errbuf = malloc(PCAP_ERRBUF_SIZE);
  pcap_t *handle = NULL;
  openDevice(&iFlag, &handle, &errbuf);

  signal(SIGINT,ctrl_c);
  pcap_loop(handle, -1 , got_packet, (u_char*) &vFlag);

  /*else
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

pcap_t *handle;
void ctrl_c(int n)
{
    printf("\nCATCH PACKET END\n");
    pcap_close(handle);
    exit(0);
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
  const struct ether_header *ethernet;
  const struct ip *ip;
  const struct tcphdr *tcp;
  const struct udphdr *udp;
  struct arphdr *arp;
  u_char* trame;
  int size_ethernet = sizeof(struct ether_header);
  int size_ip;
  int size_tcp;
  int size_trame;
  int *vFlag = (int *) args;

  ethernet = (struct ether_header*)(packet);
  ip = (struct ip*)(packet+size_ethernet);
  size_ip=IP_HL(ip)*4;
  tcp = (struct tcphdr*)(packet+size_ip+size_ethernet);
  size_tcp=sizeof(struct tcphdr);
  udp = (struct udphdr*)(packet + sizeof(struct ether_header) + ip->ip_len*4);
  arp = (struct arphdr*)(packet+14);

  printf("Caught packet with length of [%d]\n", header->len);
  printArp(arp, *vFlag);
  printEther(ethernet,*vFlag);
  printIP(ip, *vFlag);
  switch(ip->ip_p)
  {
    case IPPROTO_TCP:
      printTcp(tcp, *vFlag);
      break;
    case IPPROTO_UDP:
      printUdp(udp, *vFlag);
      if((ntohs(udp->source)==IPPORT_BOOTPS && ntohs(udp->dest)==IPPORT_BOOTPC) ||
                (ntohs(udp->dest)==IPPORT_BOOTPS && ntohs(udp->source)==IPPORT_BOOTPC)){
                printBootp((struct bootp*) (packet + sizeof(struct ether_header) + ip->ip_len*4+8),*vFlag);
      }
      break;
    default:
      printf("Unknown Protocol\n");
      break;
  }

  trame = (u_char *)(packet + size_ethernet + size_ip + size_tcp);
  size_trame = ntohs(ip->ip_len) - (size_ip + size_tcp);
  if (size_trame > 0)
  {
    printf("DATA (%d bytes):\n", size_trame);
    printAscii(trame, size_trame);
  }
  printf("\n");
  printf("\n");
  printf("\n");
  return;
}

void printIP(const struct ip* ip, int verbosite)
{
  char *aux = inet_ntoa(ip->ip_src);
  char *ab = strcpy(malloc(strlen(aux)+1), aux);
  char *bux = inet_ntoa(ip->ip_dst);
  char *cd = strcpy(malloc(strlen(aux)+1), bux);
  printf("**********IP**********\n");
  printf("From IP: %s\nTo: %s\n",ab,cd);
  if(verbosite>1)
  {
    printf("Version: %d\n", IP_V(ip));
    printf("Length: %d\n", ip->ip_len);
    printf("Type de service : %d\n", ip->ip_tos);
    printf("Identification : %d\n", ip->ip_id);
    if(verbosite>2)
    {
      printf("Fragment offset: %d\n", ip->ip_off);
      printf("Time to live: %d\n", ip->ip_ttl);
      printf("Checksum: %d\n", ip->ip_sum);
      printPacket((u_char *) ip, sizeof(struct ip));
    }
  }
  printf("\n");
}

void printEther(const struct ether_header* ethernet, int verbosite)
{
  printf("**********ETHERNET**********\n");
  if(verbosite > 1)
  {
    printf("Destination host address : ");
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
    ((unsigned)ethernet->ether_dhost[0]),
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
  printf("\n");
}
void printTcp(const struct tcphdr* tcp, int verbosite)
{
  printf("***********TCP*********\n");
  printf("Source port: %u\n", ntohs(tcp->source));
  printf("Destination port: %u\n", ntohs(tcp->dest));
  if(verbosite ==1)
  {
    printf("Flag:");
    if(tcp->urg != 0 )
      printf("URGENT ");
    if(tcp->ack != 0 )
      printf("ACK ");
    if(tcp->psh != 0 )
      printf("PUSH ");
    if(tcp->rst != 0 )
      printf("RESET ");
    if(tcp->syn != 0 )
      printf("SYN ");
    if(tcp->fin != 0 )
      printf("FINISH ");
    printf("\n");
    }
    else
    {
      printf("Flags URGENT : %d\n",tcp->urg);
      printf("Flags ACK : %d\n",tcp->ack);
      printf("Flags PUSH : %d\n",tcp->psh);
      printf("Flags RESET : %d\n",tcp->rst);
      printf("Flags SYN : %d\n",tcp->syn);
      printf("Flags FINISH : %d\n",tcp->fin);
    }
    if(verbosite > 2)
    {
      //printf("Data Offset:%d\n", ntohs(tcp->th_off));
      printf("Window: %d\n", ntohs(tcp->window));
      printf("Checksum: %d\n",ntohs(tcp->check));
      printf("Urgent Pointer: %d\n", ntohs(tcp->urg_ptr));
      printPacket((const u_char*) tcp, tcp->doff*4);
      printf("\n");
    }

  printf("\n");
}
void printUdp(const struct udphdr* udp, int verbosite)
{
  printf("**********UDP**********\n");
  printf("Source port: %u\n",ntohs(udp->source));
  printf("Destination port: %u\n", ntohs(udp->dest));
  if(verbosite > 1)
  {
    printf("Header size: %d\n", ntohs(udp->len));
    printf("Checksum: %d\n", ntohs(udp->check));
    if(verbosite > 2)
    {
      printPacket((const u_char*) udp, ntohs(udp->len));
      printf("\n");
    }
  }
  printf("\n");
}

void printArp(struct arphdr* arp, int verbosite)
{
  printf("**********ARP**********\n");
  if(verbosite > 1)
  {
    printf("Hardware type : %u (%s) \n", ntohs(arp->ar_hrd),(ntohs(arp->ar_hrd) == 1) ? "Ethernet" : "Inconnu");
    printf("Protocol : %u (%s) \n", arp->ar_pro,(ntohs(arp->ar_pro) == ETHERTYPE_IP) ? "IPv4" : "Inconnu");
    printf("Operation : %u (%s) \n", ntohs(arp->ar_op), (ntohs(arp->ar_op) == ARP_REQUEST)? "REQUEST" : "REPLY");
    if(verbosite > 2)
    {
        u_char * content = (u_char *) arp + sizeof(struct arphdr);
        printf("Source Mac address: %02x:%02x:%02x:%02x:%02x:%02x\n",(arp->content[0]),(arp->content[1]),(arp->content[2]),(arp->content[3]),(arp->content[4]),(arp->content[5]));
        printf("Destination Mac address: %02x:%02x:%02x:%02x:%02x:%02x\n", (arp->data[0]),(arp->data[1]),(arp->data[2]),(arp->data[3]),(arp->data[4]),(arp->data[5]));

        printf("Source IP address: %d.%d.%d.%d\n",(arp->data[0]),(arp->data[1]),(arp->data[2]),(arp->data[3]));
        printf("Destination IP address: %d.%d.%d.%d\n",(arp->data[0]),(arp->data[1]),(arp->data[2]),(arp->data[3]));
    }
  }
  printf("\n");

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
                 case TAG_NETBIOS_NS:
                 j =i+3;
                 printf("Name server IP address: %d",bp->bp_vend[j]);
                 for(j++;j<bp->bp_vend[i+1]+i+3;j++)
                     printf(".%d",bp->bp_vend[j]);
                 printf("\n");
                 break;
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
        printf("\n");

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
