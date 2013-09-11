#include "elfit.h"

/* loads an ELF host
 * into an Elfit_t */
int load_host(char *name, Elfit_t *host)
{
    int hfd;
    struct stat hst;
    size_t statsz;

    if ((hfd = open(name, O_RDONLY)) < 0)
    {
        perror("load open host");
        return -1;
    }

    if (fstat(hfd, &hst))
    {
        perror("load fstat host");
        return -1;
    }

    statsz = (size_t) sizeof(struct stat);

    if ((host->mem = malloc(hst.st_size)) == NULL)
    {
        perror("host mem malloc");
        return -1;
    }

    if ((host->file = malloc(statsz)) == NULL)
    {
        perror("host file alloc");
        return -1;
    }

    memcpy(host->file, &hst, statsz);
    host->name = name;

    return 1;
}

void unload_host(Elfit_t *host)
{
    free(host->mem);
    free(host->file);
}
