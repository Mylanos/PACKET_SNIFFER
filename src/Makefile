CC=gcc
LFLAGS= -Wall
RFLAGS= -lpcap

main: main.c
	$(CC) $(LFLAGS) main.c -o $@ $< $(RFLAGS)
clean:
	-rm *.o $(objects)
