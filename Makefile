OBJS=src/main.o src/injectors.o src/redirectors.o src/parasite.o src/usage.o src/util.o
CC=gcc
CFLAGS=-Iinclude/

elfit: $(OBJS) 
	$(CC) -o elfit $(OBJS) 

install: elfit
	cp elfit /usr/bin

clean: 
	rm elfit src/*.o 
