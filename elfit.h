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
int entry_redirect(Elfit_t *, unsigned long);

/* Injectors */
uint32_t textpadding_inject(Elfit_t *, char *, uint32_t, unsigned long);

/* Utilities */
int load_host(char *, Elfit_t *);

void unload_host(Elfit_t *);

int get_section_by_name(char *, Elfit_t *);
