CXX=gcc
PARAMSTD=-g
PARAMOBJ=-c


all: crypto.h crypto.c crypto.o xxtea.c
	$(CXX) $(PARAMSTD) -o xxtea xxtea.c crypto.o

crypto.o: crypto.c crypto.h
	$(CXX) $(PARAMSTD) $(PARAMOBJ) crypto.c

clean:
	rm -f *~ *.bak *.o