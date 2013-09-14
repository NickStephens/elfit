#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <elf.h>

#define PAGE_SIZE 4096
#define TMP "tmp.bin"

typedef struct {
    char *name;
    unsigned char *mem;
    struct stat *file; 
} Elfit_t;

/* Redirectors */
int entry_redirect_32(Elfit_t *, unsigned long);
int entry_redirect_64(Elfit_t *, unsigned long);

Elf32_Addr got_redirect_32(Elfit_t *, char *, unsigned long);

/* Injectors */
uint32_t textpadding_inject_32(Elfit_t *, char *, uint32_t, unsigned long);
uint64_t textpadding_inject_64(Elfit_t *, char *, uint64_t, unsigned long);

/* Utilities */
int load_host(char *, Elfit_t *);

void unload_host(Elfit_t *);

int get_section_by_name_32(char *, Elfit_t *);
