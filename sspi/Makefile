CC = gcc
RM = del
LDFLAGS = -lsecur32
CFLAGS = -I.. -DWINVER=0x500 -Wall

CLIENT_OBJS = client.o base64.o getopt.o clipboard.o errmsg.o userio.o
CLIENT_OBJS += flags.o common.o

client.exe: $(CLIENT_OBJS)
	$(CC) -o $@ $(CLIENT_OBJS) $(LDFLAGS)

base64.o: ../base64.c
	$(CC) $(CFLAGS) -c ../base64.c -o $@

.c.o:
	$(CC) $(CFLAGS) -c $<

clean:
	$(RM) client.exe $(CLIENT_OBJS)

