#ifndef GETOPT_H
#define GETOPT_H

#ifdef __cplusplus
extern "C" {
#endif

extern char *optarg;
extern int optind, opterr, optopt;

int getopt(int argc, char * const argv[], const char *optstring);

struct option {
  const char* name;       
  int has_arg;          
  int* flag;            
  int val;               
};

#define no_argument        0
#define required_argument  1
#define optional_argument  2


#ifdef __cplusplus
}
#endif

#endif /* GETOPT_H */