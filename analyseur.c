#include <pcap.h> 
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void getOptions(int argc, char ** argv, int * vFlag, char ** iFlag, char ** oFlag, char ** fFlag);
void checkIfSudo();
void openDevice(char * device,pcap_t * handle, char * errbuf);
void printHelp(char ** argv);

int main(int argc, char ** argv)
{
  checkIfSudo();
  int vFlag = 0;
  char *iFlag = NULL;
  char *oFlag = NULL;
  char *fFlag = NULL;

  getOptions(argc, argv, &vFlag, &iFlag, &oFlag, &fFlag);

  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *handle = NULL;
  openDevice(iFlag, handle, errbuf);

  //struct pcap_pkthdr header;	/* The header that pcap gives us */
	//const u_char *packet;		/* The actual packet */
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


}

void checkIfSudo()
{
  if(getuid() != 0)
  {
    printf("Please run as root.\n");
    exit(EXIT_FAILURE);
  }
}

void openDevice(char * device, pcap_t * handle, char * errbuf)
{
  struct bpf_program fp;
  char filter_exp[] = "port 23";
  bpf_u_int32 mask = 0;  /* The netmask of our sniffing device */
  bpf_u_int32 net = 0;  /* The IP of our sniffing device */
  printf("Opening device %s...\n", device);

  handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf); //Start sniffing
  if (handle == NULL)
  {
    fprintf(stderr, "Couldn't open device %s: %s\n", device, errbuf);
    exit(EXIT_FAILURE);
 }
  if (pcap_datalink(handle) != DLT_EN10MB) { //Indicates the type of link layer headers
  fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", device);
    //fails if the device doesn't supply Ethernet headers
    exit(EXIT_FAILURE);
 }
  printf("Device %s opened succesfully\n", device);
  if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
    fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
    exit(EXIT_FAILURE);
   }
}

void printHelp(char ** argv)
{
    printf("Usage: %s [-f filter] -i interface -o file -v verbosity\n",argv[0]);
    printf("  where -o and -i are mandatory and exclusive,\n");
    printf("        -f is not mandatory,\n");
    printf("        -v is mandatory and is an integer in [1,3] with 1 being low verbosity and 3 high verbosity.\n");
    exit(EXIT_SUCCESS);
}
