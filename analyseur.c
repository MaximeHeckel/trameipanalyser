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
    printf("%x ", packet[i]);
  }
  printf("\n");
}
void printHexPacket(const u_char * trame, int length, int offset)
{
  int i;
  int gap;
  const u_char *tape;

  printf("%05d   ", offset);
  tape = trame;
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

  /* ascii (if printable) */
  tape = trame;
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

  void print_payload(const u_char *trame, int len)
  {

        int len_rem = len;
        int line_width = 16;                        /* number of bytes per line */
        int line_len;
        int offset = 0;                                        /* zero-based offset counter */
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
  }

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
  const struct sniff_ethernet *ethernet;
  const struct sniff_ip *ip;
  const struct sniff_tcp *tcp;
  const struct sniff_udp *udp;
  const u_char* trame;
  int size_ethernet = sizeof(struct sniff_ethernet);
  int size_ip;
  int size_tcp;
  int size_trame;

  ethernet = (struct sniff_ethernet*)(packet);
  ip = (struct sniff_ip*)(packet+size_ethernet);
  size_ip=IP_HL(ip)*4;
  tcp = (struct sniff_tcp*)(packet+size_ip+size_ethernet);
  size_tcp=TH_OFF(tcp)*4;
  udp = (struct sniff_udp*)(packet+SIZE_UDP+size_ethernet);

  printf("TRACE: \n");
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

  printf("Ether_type : [%i]\n", ethernet->ether_type);

  char *aux = inet_ntoa(ip->ip_src);
  char *ab = strcpy(malloc(strlen(aux)+1), aux);
  char *bux = inet_ntoa(ip->ip_dst);
  char *cd = strcpy(malloc(strlen(aux)+1), bux);
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

        /* compute tcp payload (segment) size */
        size_trame = ntohs(ip->ip_len) - (size_ip + size_tcp);

        /*
         * Print payload data; it might be binary, so don't just
         * treat it as a string.
         */
        if (size_trame > 0) {
                printf("DATA (%d bytes):\n", size_trame);
                print_payload(trame, size_trame);
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

