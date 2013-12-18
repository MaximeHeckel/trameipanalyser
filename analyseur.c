#include <pcap.h> 
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void getOptions(int argc, char ** argv, int * vFlag, char * iFlag, char * oFlag, char * fFlag);

int main(int argc, char ** argv)
{
  int vFlag = 0;
  char *iFlag = NULL;
  char *oFlag = NULL;
  char *fFlag = NULL;

  getOptions(argc, argv, &vFlag, iFlag, oFlag, fFlag);
  return 0;
}

void getOptions(int argc, char ** argv, int * vFlag, char * iFlag, char * oFlag, char * fFlag)
{
  int index;
  int c;
  // o v f i
  int optionsPresent[4] = {0,0,0,0};   
  opterr = 0;
     
  while ((c = getopt (argc, argv, "i:o:v:f:")) != -1)
    switch (c)
    {
      case 'o':
        oFlag = optarg;
        optionsPresent[0] = 1;
        break;
      case 'v':
        *vFlag = atoi(optarg);
        if( *vFlag < 1 || *vFlag > 3)
        {
          fprintf(stderr, "Option -v requires a value in [1,3]\n");
          exit(EXIT_SUCCESS);
        }
        optionsPresent[1] = 1;
        break;
      case 'f':
        fFlag = optarg;
        optionsPresent[2] = 1;
        break;
      case 'i':
        iFlag = optarg;
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
          exit(EXIT_SUCCESS);
      default:
        abort ();
    }
     
    printf ("vFlag = %d, iFlag = %s, fFlag = %s, oFlag = %s\n",*vFlag, iFlag, fFlag, oFlag);
     
    for (index = optind; index < argc; index++)
      printf ("Non-option argument %s\n", argv[index]);
   
    int missingOptions = 0;
    if( ! optionsPresent[0])
    {
      printf("Option -o not present.\n");
      missingOptions = 1;
    }
    if( ! optionsPresent[1])
    {
      printf("Option -v not present.\n");
      missingOptions = 1;
    }
    if( ! optionsPresent[3])
    {  
      printf("Option -i not present.\n");
      missingOptions = 1;
    }
    if(missingOptions)
    {
      exit(EXIT_SUCCESS);
    }

}
