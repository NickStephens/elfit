#include "elfit.h"

/* currently just a wrapper for posttext inject */
int main(int argc, char *argv[])
{
    char *parasite;
    struct stat hst;
    int hfd;
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

    if ((parasite = malloc(strlen(argv[2]))) == NULL)
    {
        perror("malloc parasite str");
        exit(-1);
    }

    strncpy(parasite, argv[2], strlen(argv[2]));

    /* PATCH TO (ENTRY [NULL], X) */
    entry = textpadding_inject(&host, parasite, patch_position);
    reload_host(argv[1], &host);

    entry_redirect(&host, entry);

    free(parasite);
}
