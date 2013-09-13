CC = gcc

elfit: main.o redirectors.o injectors.o util.o usage.o
	$(CC) -o elfit main.o redirectors.o injectors.o util.o usage.o

clean: 
	rm *.o 
