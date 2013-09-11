#include "elfit.h"

/* currently just a wrapper for posttext inject */
int main(int argc, char *argv[])
{
    struct stat pst;
    int fd;
    unsigned long entry;

    if (argc < 4)
    {
        printf("usage: %s <host> <parasite> <patch_position>\n", argv[0]);
        exit(1);
    }

    fd = open(argv[2], O_RDONLY); 

    fstat(fd, &pst);

    entry = posttext_inject(argv[1], argv[2], pst.st_size);

    entry_redirect(argv[1], entry);
}
