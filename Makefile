CC = gcc


elfit: main.o redirectors.o injectors.o util.o usage.o parasite.o
	$(CC) -o elfit main.o redirectors.o injectors.o util.o usage.o parasite.o

install: elfit
	cp elfit /usr/bin

clean: 
	rm *.o 
