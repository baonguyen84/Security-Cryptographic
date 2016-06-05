CC=gcc
COPTS= -std=c99 -Wall -pedantic -D_GNU_SOURCE
ALL=crypto

all: $(ALL)

JUNK=*.o *~ *.dSYM

tar:
	tar -czvf CS427-Project2-BaoNguyen-11354901.tar.gz Makefile README ptext.txt crypto.c crypto.h
clean:
	-rm -rf $(JUNK)

clobber:
	-rm -rf $(JUNK) $(ALL)
crypto: crypto.o
	$(CC) $(COPTS) $^ -o $@

.c.o:
	$(CC) -c $(COPTS) $<
crypto.o:crypto.c crypto.h


