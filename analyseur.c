#include "analyseur.h"

void getOptions(int argc, char ** argv, int * vFlag, char ** iFlag, char ** oFlag, char ** fFlag);
void checkIfSudo();
void openDevice(char ** device,pcap_t ** handle, char ** errbuf);
void printHelp(char ** argv);
void sniffPacket(pcap_t ** handle,struct pcap_pkthdr *  header, const u_char **packet);
void printPacket(const u_char * packet, int length);
void printHexPacket(const u_char * payload, int length, int offset);
void print_payload(const u_char payload, int len);
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void openFile(char * name, FILE ** file);


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
    printf("%x ", packet[i]);
  }
  printf("\n");
}
void printHexPacket(const u_char * payload, int length, int offset)
{
  int i;
  int gap;
  const u_char *tape;

  printf("%05d   ", offset);
  tape = payload;
  for(i = 0; i < length; i++) {
    printf("%02x ", *tape);
    tape++;
    /* print extra space after 8th byte for visual aid */
    if (i == 7)
      printf(" ");
  }
  /* print space to handle line less than 8 bytes */
  if (length < 8)
    printf(" ");

  /* fill hex gap with spaces if not full line */
  if (length < 16) {
    gap = 16 - length;
    for (i = 0; i < gap; i++) {
      printf("   ");
    }
  }
  printf("   ");

  /* ascii (if printable) */
  tape = payload;
  for(i = 0; i < length; i++) {
    if (isprint(*tape))
      printf("%c", *tape);
    else
      printf(".");
    tape++;
    }
    printf("\n");

return;
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
  const struct sniff_ethernet *ethernet;
  const struct sniff_ip *ip;
  const struct sniff_tcp *tcp;
  const struct sniff_udp *udp;
  //const char* payload;
  int size_ethernet = sizeof(struct sniff_ethernet);
  int size_ip;
  int size_tcp;
  //int size_payload;

  ethernet = (struct sniff_ethernet*)(packet);
  ip = (struct sniff_ip*)(packet+size_ethernet);
  size_ip=IP_HL(ip)*4;
  tcp = (struct sniff_tcp*)(packet+size_ip+size_ethernet);
  size_tcp=TH_OFF(tcp)*4;
  udp = (struct sniff_udp*)(packet+SIZE_UDP+size_ethernet);



  /****************************/
  //SOLUTION MATCHED IP

  char *tab;

  printf("TRACE: \n");
  printf("Destination host address : ");
        printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
    ntohs ((unsigned)ethernet->ether_dhost[0]),//ntohs sur la globalité
    ntohs ((unsigned)ethernet->ether_dhost[1]),
    ntohs ((unsigned)ethernet->ether_dhost[2]),
    ntohs ((unsigned)ethernet->ether_dhost[3]),
    ntohs ((unsigned)ethernet->ether_dhost[4]),
    ntohs ((unsigned)ethernet->ether_dhost[5]));
    printf("Source host address : ");
        printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
    ntohs ((unsigned)ethernet->ether_shost[0]),
    ntohs ((unsigned)ethernet->ether_shost[1]),
    ntohs ((unsigned)ethernet->ether_shost[2]),
    ntohs ((unsigned)ethernet->ether_shost[3]),
    ntohs ((unsigned)ethernet->ether_shost[4]),
    ntohs ((unsigned)ethernet->ether_shost[5]));
    //printf("%x\n",ntohs(ethernet->ether_shost));
        //printf("Content : [%s]\n", ethernet->ether_shost);
        printf("Ether_type : [%i]\n", ethernet->ether_type);
  printf("From IP: %s\nTo: %s\n",inet_ntoa(ip->ip_src),inet_ntoa(ip->ip_dst));

  //Switch sur type protocol
  switch(ip->ip_p)
  {
    case IPPROTO_IP:
      printf("Protocole IP\n");
      printf("Version = %d\n", ip->ip_vhl);
      printf("Length = %d\n", ip->ip_len);
      printf("\n");
      break;
    case IPPROTO_TCP:
      printf("Protocole TCP\n");
      printf("Source Port = %d\n" ,ntohs(tcp->th_sport));
      printf("Destination Port = %d\n", ntohs(tcp->th_dport));
      printf("Data Offset = %d\n", ntohs(tcp->th_offx2));
      printf("Window = %d\n", ntohs(tcp->th_win));
      printf("\n");
      break;
    case IPPROTO_UDP:
      printf("Protocole UDP\n");
      printf("Source Port = %d\nDestination Port = %d\n", ntohs(udp->uh_sport), ntohs(udp->uh_dport));
      printf("\n");
      break;
    default:
      printf("Protocole Unknown\n");
      break;
  }
  return;
}

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

