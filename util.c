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
        perror("host file malloc");
        return -1;
    }

    if (read(hfd, host->mem, hst.st_size) != hst.st_size)
    {
        perror("host read");
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

int reload_host(char *name, Elfit_t *host)
{
    unload_host(host);

    if (load_host(name, host) == -1)
    {
        perror("reload load_host");
        return -1;
    }

    return 1;
}
