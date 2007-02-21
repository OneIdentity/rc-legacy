

.SUFFIXES: .xml .unpg .txt .html
.xml.unpg:
	xml2unpg $<
.xml.txt:
	xml2rfc $< $@
.xml.html:
	xml2html $< 


default: pgss

OBJS=	pgss-config.o \
	pgss-getprogname.o \
	pgss-oidstr.o \
	pgss-gss2.o \
	pgss-dlprov.o \
	test.o

CPPFLAGS=	-I.
CFLAGS = -ggdb -O2
pgss: $(OBJS)
	$(LINK.c) -o $@ $(OBJS)

#default: design.unpg
clean:
	rm -f design.txt design.html design.unpg
	rm -f pgss $(OBJS)


