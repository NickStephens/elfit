#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <elf.h>

#define PAGE_SIZE 4096
#define TMP "tmp.bin"

/* Redirectors */
int entry_redirect(char *, unsigned long);

/* Injectors */
int posttest_inject(char *, struct stat *, char *, uint8_t);

