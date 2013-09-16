CC = gcc


elfit: main.o redirectors.o injectors.o util.o usage.o
	$(CC) -o elfit main.o redirectors.o injectors.o util.o usage.o

install: elfit
	cp elfit /usr/bin

clean: 
	rm *.o 
