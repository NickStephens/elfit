#include <sys/mman.h>
#include <stdio.h>

int main(void)
{
	printf("MAP_ANONYMOUS: %d\n", MAP_ANONYMOUS);
	printf("MAP_PRIVATE: %d\n", MAP_PRIVATE);
	printf("PROT_EXEC: %d\n", PROT_EXEC);
	printf("PROT_WRITE: %d\n", PROT_WRITE);
	printf("PROT_READ: %d\n", PROT_READ);
}
