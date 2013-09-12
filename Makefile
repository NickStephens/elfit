CC = gcc

elfit: main.o redirectors.o injectors.o util.o
	$(CC) -o elfit main.o redirectors.o injectors.o util.o

clean: 
	rm *.o 
