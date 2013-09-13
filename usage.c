#include "elfit.h"

static void print_help(char opt, char *prog)
{
    if (opt != 0x00)
        printf("unrecognized option: %c\n", opt); 

    printf(
    "usage: %s [options] <host>\n"
    "options:\n"
    "-p <parasite>  inject parasite by padding text\n"
    "-r <parasite>  inject parasite by reverse padding\n"
    "-s <sharedobj> inject shared object\n"
    "-a <reloc>     inject relocatable\n"
    "-e             use entry point redirection\n"
    "-g <symbol>    hijack symbol's got entry\n"
    "-c             use ctor redirection\n"
    "-d             use dtor redirection\n"
    "-v <addr>      patch parasite with addr for jmp point\n"
    "-q <position>  byte index into parasite with which to patch with return addr\n",
    prog);
}

opts_t * usage(int argc, char *argv[])
{
    opts_t *opts;
    int c;

    opts = malloc(sizeof(opts_t));

    if (argc < 3)
    {
        print_help(0, argv[0]); 
        return NULL;
    }

    memset(opts, 0, sizeof(opts_t));
    while((c = getopt(argc, argv, "p:r:s:a:eg:cdv:q:h")) != -1)
    {
        switch(c)
        {
            case 'p': strncpy(opts->parasite, optarg, MAX_FILENAME-1); 
                opts->textpadding++; break;
            case 'r': strncpy(opts->parasite, optarg, MAX_FILENAME-1);  
                opts->reversepadding++; break;
            case 's': strncpy(opts->parasite, optarg, MAX_FILENAME-1);
                opts->soinject++; break;
            case 'a': strncpy(opts->parasite, optarg, MAX_FILENAME-1);
                opts->etrelinject++; break;
            case 'e': opts->entrypoint++; break;
            case 'g': strncpy(opts->pltsymbol, optarg, MAX_FILENAME-1);
                opts->gottable++; break;
            case 'c': opts->ctors++; break;
            case 'd': opts->dtors++; break;
            case 'v': opts->patch_addr = strtoul(optarg, NULL, 16); break;
            case 'q': opts->patch_pos = atoi(optarg); break;
            case 'h': print_help(0x00, argv[0]); break;
            default: print_help((char) c, argv[0]); break;
        }
    } 
    
    strncpy(opts->host, argv[argc-1], MAX_FILENAME-1);  
}

void opts_debug(opts_t *opts)
{
    printf("parasite: %s\n", opts->parasite);
    printf("textpadding: %d\n", opts->textpadding);
    printf("patch_addr: 0x%x\n", opts->patch_addr);
    printf("host: %s\n", opts->host);
}
