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

/* Retrieve a section's index 
 * given the name of section and
 * a Elfit_t */
int get_section_by_name_32(char *name, Elfit_t *host)
{
    Elf32_Ehdr *ehdr;
    Elf32_Shdr *shdr;
    char *shstrtab;
    int shstrndx, i;

    ehdr = (Elf32_Ehdr *) host->mem;
    shdr = (Elf32_Shdr *) (host->mem + ehdr->e_shoff);
    shstrtab = host->mem + shdr[ehdr->e_shstrndx].sh_offset;

    for (i = 0; i < ehdr->e_shnum; i++)
    {
        if (strcmp(&shstrtab[shdr[i].sh_name], name) == 0)
            return i;
    }

    return -1;
}

int get_section_by_name_64(char *name, Elfit_t *host)
{
    Elf64_Ehdr *ehdr;
    Elf64_Shdr *shdr;
    char *shstrtab;
    int shstrndx, i;

    ehdr = (Elf64_Ehdr *) host->mem;
    shdr = (Elf64_Shdr *) (host->mem + ehdr->e_shoff);
    shstrtab = host->mem + shdr[ehdr->e_shstrndx].sh_offset;

    for (i = 0; i < ehdr->e_shnum; i++)
    {
        if (strcmp(&shstrtab[shdr[i].sh_name], name) == 0)
            return i;
    }

    return -1;
}

int str_to_mode(char *str)
{
    if (!strcmp(str, "init"))
    {
        return HIJACK_INIT;
    }
    else if (!strcmp(str, "fini"))
    {
        return HIJACK_FINI;
    }
    else if (!strcmp(str, "main"))
    {
        return HIJACK_MAIN;
    }
    else
    {
        printf("[-] unrecognized hijack mode chosen\n");
        exit(-1);
    }
}

