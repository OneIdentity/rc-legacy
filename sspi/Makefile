CC = gcc
RM = del
LDFLAGS = -lsecur32 -ladvapi32
CFLAGS = -I.. -DWINVER=0x500 -Wall

COMMON_OBJS = base64.o getopt.o clipboard.o errmsg.o userio.o
COMMON_OBJS += flags.o common.o wrap.o version.o

CLIENT_OBJS = client.o $(COMMON_OBJS)
SERVER_OBJS = server.o $(COMMON_OBJS) deleg.o

ALL_PROGS = client.exe server.exe
all: $(ALL_PROGS)

client.exe: $(CLIENT_OBJS)
	$(CC) -o $@ $(CLIENT_OBJS) $(LDFLAGS)

server.exe: $(SERVER_OBJS)
	$(CC) -o $@ $(SERVER_OBJS) $(LDFLAGS)

base64.o: ../base64.c
	$(CC) $(CFLAGS) -c ../base64.c -o $@

.c.o:
	$(CC) $(CFLAGS) -c $<

version.c: mkversion.vbs ../configure.ac
	cscript //NoLogo mkversion.vbs

clean:
	$(RM) $(ALL_PROGS) $(CLIENT_OBJS) $(SERVER_OBJS)
	$(RM) version.c

