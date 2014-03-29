#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <elf.h>

#define PAGE_SIZE 4096
#define MAX_FILENAME 100
#define MAX_SEARCH_LEN 0x100
#define TMP "tmp.bin"

#define HIJACK_INIT 1
#define HIJACK_FINI 2
#define HIJACK_MAIN 3

typedef struct {
    char *name;
    unsigned char *mem;
    struct stat *file; 
} Elfit_t;

typedef struct {
    /* name of host file */
    char host[MAX_FILENAME];
    /* name of parasite file */
    char parasite[MAX_FILENAME];
    /* XOR key for polymorphism */
    char polymorphic_key;
    /* address to patch parasite code with */
    unsigned long patch_addr;
    /* patch position */
    unsigned int patch_pos;
    /* entrypoint redirect */
    unsigned int entrypoint;
    /* got table redirect */
    unsigned int gottable; 
    char pltsymbol[MAX_FILENAME];
    /* ctors redirect */
    unsigned int ctors; 
    /* dtors redirect */
    unsigned int dtors; 
    /* arbitrary function hook */
    unsigned int arbfunc; 
    /* __libc_start_main arg hijacking*/
    unsigned int startmain;
    unsigned int startmain_mode;


    /* text padding method */
    unsigned int textpadding; 
    /* reverse padding method */
    unsigned int reversepadding; 
    /* shared object method */
    unsigned int soinject; 
    /* et_rel method */
    unsigned int etrelinject; 

    /* cross architecture infection */
    unsigned int cross_infect;
} opts_t;


/* Redirectors */
off_t entry_redirect_32(Elfit_t *, uint32_t *);
off_t entry_redirect_64(Elfit_t *, uint64_t *);

off_t got_redirect_32(Elfit_t *, char *, uint32_t *);
off_t got_redirect_64(Elfit_t *, char *, uint64_t *);

int commit_redirect_32(Elfit_t *, off_t, uint32_t);
int commit_redirect_64(Elfit_t *, off_t, uint64_t);


/* Injectors */
uint32_t textpadding_inject_32(Elfit_t *, char *, uint32_t, uint32_t);
uint64_t textpadding_inject_64(Elfit_t *, Elfit_t *, uint64_t, uint64_t);

/* Utilities */
int load_host(char *, Elfit_t *);
void unload_host(Elfit_t *);

int get_section_by_name_32(char *, Elfit_t *);
int get_section_by_name_64(char *, Elfit_t *);

/* Interface */
opts_t *usage(int, char **);
