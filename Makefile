LDLIBS=-lpcap -lpthread

all: arp-spoof

arp-spoof: main.o ethhdr.o ip.o mac.o getadds.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f arp-spoof *.o