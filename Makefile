#for 32bit machines
LIBDIR = /opt/quest/lib
INCDIR = /opt/quest/include

all: vasidmap vasidmapd
	
vasidmap:
	cc -g -I $(INCDIR) -Wl,-rpath -Wl,$(LIBDIR) -L $(LIBDIR) -l vas -o vasidmap vasidmap.c

vasidmapd:
	cc -g -I $(INCDIR) -Wl,-rpath -Wl,$(LIBDIR) -L $(LIBDIR) -l vas -o vasidmapd vasidmapd.c

clean:
	rm -f vasidmap vasidmapd
