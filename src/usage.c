#include <elfit.h>
#include <getopt.h>

static struct option long_options[] = 
    {
        { "parasite", required_argument, NULL, 'p'},
        { "text", no_argument, NULL, 't'},
        { "note", no_argument, NULL, 'n'},
        { "reverse", no_argument, NULL, 'r'},
        { "data", no_argument, NULL, 'w'},
        { "shared", no_argument, NULL, 's'},
        { "relinjex", no_argument, NULL, 'a'},
        { "got", required_argument, NULL, 'g'},
        { "entrypoint", no_argument, NULL, 'e'},
        { "ctor", no_argument, NULL, 'c'},
        { "dtor", no_argument, NULL, 'd'},
        { "start-main", required_argument, NULL, 'm'},
        { "patch-addr", required_argument, NULL, 'v'},
        { "patch-position", required_argument, NULL, 'q'},
        { "in-segment-poly", required_argument, NULL, 'z'},
        { "cross", no_argument, NULL, 'x'},
        { "help", no_argument, NULL, 'h'},
        { 0, 0, 0, 0}
    };
 
int option_index = 0;

static void print_help(char opt, char *prog)
{
    if (opt != 0x00)
        printf("unrecognized option: %c\n", opt); 

    printf(
    "usage: %s [options] <host>\n"
    "options:\n"
    "-p, --parasite <parasite>  specify parasite file\n"
    "\n"
    "INJECTION TECHNIQUES:\n"
    "\t-t, --text               text padding infection\n"
    "\t-r, --reverse            reverse text padding infection\n"
    "\t-w, --data               data padding infection\n"
    "\t-s, --shared <sharedobj> inject shared object\n"
    "\t-a, --relinjex           relocatable injection\n"
    "\t-n, --note               note injection\n"
    "\n"
    "REDIRECTION TECHNIQUES:\n"
    "\t-g, --got <symbol>               hijack symbol's got entry\n"
    "\t-e, --entrypoint                 use entry point redirection\n"
    "\t-c, --ctor                       use ctor redirection\n"
    "\t-d, --dtor                       use dtor redirection\n"
    "\t-m, --start-main init|fini|main  hijack chosen __libc_start_main arg\n"
    "\n"
    "PARASITE MODIFICATION:\n"
    "\t-v, --patch-addr <addr>         explicitly patch parasite with addr for jmp point\n"
    "\t-q, --patch-position <position> byte index into parasite with which to patch with return addr\n"
    "\t-z, --in-segment-poly <key>     mutates the parasite with key, may mark injection segment writable\n"
    "-x                 cross architecture infection, infect executables on i386 if on x64 or infect executables of x64 if on i368\n",
    prog);
    exit(-1);
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
    while((c = getopt_long(argc, argv, "z:p:trsnaeg:cdm:v:q:xh", long_options, &option_index)) != -1)
    {
        switch(c)
        {
            case 'z': opts->polymorphic_key = optarg[0]; break;
            case 'p': strncpy(opts->parasite, optarg, MAX_FILENAME-1); break;
            case 't': 
                opts->injection_method = TEXT_INJECT; break;
            case 'r': 
                opts->injection_method = REVERSE_INJECT; break;
            case 's': 
                opts->injection_method = SO_INJECT; break;
            case 'w':
                opts->injection_method = DATA_INJECT; break;
            case 'a': 
                opts->injection_method = ETREL_INJECT; break;
            case 'n':
                opts->injection_method = NOTE_INJECT; break;
            case 'e': opts->redirection_method = ENTRY_REDIR; break;
            case 'g': strncpy(opts->pltsymbol, optarg, MAX_FILENAME-1);
                opts->redirection_method = GOT_REDIR; break;
            case 'c': opts->redirection_method = CTORS_REDIR; break;
            case 'd': opts->redirection_method = DTORS_REDIR; break;
            case 'm': opts->startmain_mode = str_to_mode(optarg); 
            opts->redirection_method = STARTMAIN_REDIR; break;
            case 'v': opts->patch_addr = strtoul(optarg, NULL, 16); break;
            case 'q': opts->patch_pos = atoi(optarg); break;
            case 'x': opts->cross_infect++; break;
            case 'h': print_help(0x00, argv[0]); break;
            default: print_help((char) c, argv[0]); break;
        }
    } 
    
    strncpy(opts->host, argv[argc-1], MAX_FILENAME-1);  
}
