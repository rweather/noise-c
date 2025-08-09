#include <stdio.h>
#include <string.h>
#include "getopt.h"

char *optarg = NULL;
int optind = 1;
int opterr = 1;
int optopt = 0;

static int find_long_option(const struct option *longopts, const char *name, int namelen) {
    int i;
    for (i = 0; longopts[i].name != NULL; i++) {
        if (strncmp(longopts[i].name, name, namelen) == 0 && 
            strlen(longopts[i].name) == namelen) {
            return i;
        }
    }
    return -1;
}

int getopt_long(int argc, char * const argv[], const char *optstring,
                const struct option *longopts, int *longindex) {
    static int sp = 1;
    int c;
    char *cp;

    if (sp == 1) {
        if (optind >= argc ||
            argv[optind][0] != '-' || argv[optind][1] == '\0')
            return -1;
        else if (strcmp(argv[optind], "--") == 0) {
            optind++;
            return -1;
        }
        else if (argv[optind][0] == '-' && argv[optind][1] == '-') {
            /* Long option */
            char *name = argv[optind] + 2;
            char *eq = strchr(name, '=');
            int namelen = eq ? (eq - name) : strlen(name);
            int opt_index = find_long_option(longopts, name, namelen);
            
            if (opt_index == -1) {
                if (opterr)
                    fprintf(stderr, "%s: unrecognized option '--%.*s'\n", argv[0], namelen, name);
                optind++;
                return '?';
            }
            
            if (longindex)
                *longindex = opt_index;
            
            if (longopts[opt_index].has_arg == no_argument) {
                if (eq) {
                    if (opterr)
                        fprintf(stderr, "%s: option '--%s' doesn't allow an argument\n", argv[0], longopts[opt_index].name);
                    optind++;
                    return '?';
                }
                optarg = NULL;
            } else if (longopts[opt_index].has_arg == required_argument) {
                if (eq) {
                    optarg = eq + 1;
                } else if (++optind >= argc) {
                    if (opterr)
                        fprintf(stderr, "%s: option '--%s' requires an argument\n", argv[0], longopts[opt_index].name);
                    return '?';
                } else {
                    optarg = argv[optind];
                }
            } else { /* optional_argument */
                optarg = eq ? eq + 1 : NULL;
            }
            
            optind++;
            
            if (longopts[opt_index].flag) {
                *longopts[opt_index].flag = longopts[opt_index].val;
                return 0;
            } else {
                return longopts[opt_index].val;
            }
        }
    }

    optopt = c = argv[optind][sp];
    if (c == ':' || (cp = strchr(optstring, c)) == NULL) {
        if (opterr)
            fprintf(stderr, "%s: illegal option -- %c\n", argv[0], c);
        if (argv[optind][++sp] == '\0') {
            optind++;
            sp = 1;
        }
        return '?';
    }

    if (*++cp == ':') {
        if (argv[optind][sp+1] != '\0')
            optarg = &argv[optind++][sp+1];
        else if(++optind >= argc) {
            if (opterr)
                fprintf(stderr, "%s: option requires an argument -- %c\n", argv[0], c);
            sp = 1;
            return '?';
        } else
            optarg = argv[optind++];
        sp = 1;
    } else {
        if (argv[optind][++sp] == '\0') {
            sp = 1;
            optind++;
        }
        optarg = NULL;
    }

    return c;
}

int getopt(int argc, char * const argv[], const char *optstring) {
    return getopt_long(argc, argv, optstring, NULL, NULL);
}