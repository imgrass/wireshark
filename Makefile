CC = gcc
CFLAGS = -O2 -g -D_FORTIFY_SOURCE=2 -fPIE -fstack-protector-strong --param=ssp-buffer-size=4 -Wmissing-prototypes -Wall
CPPFLAGS = 

DESTDIR=

OBJS = main.o recv_packet.o send_packet.o parse_pcap_util.o
TEST_OBJS = test.o

LDFLAGS =  -pie -Wl,-z,relro,-z,now
DIR_LIBS = -L ./libpcap/lib/ \
		   -L ./libevent/lib

## Telling gcc directly to link libraries statically.
LIBS = -l:libpcap.a \
	   -l:libevent.a

INCLUDE = -I . \
		  -I ./libpcap/include \
		  -I ./libevent/include

# Until we have a main procedure we can link, just build object files
# to test compilation

all : wireshark

wireshark : $(OBJS)
	$(CC) $^ $(CFLAGS) $(DIR_LIBS) $(LIBS) $(INCLUDE) -o $@

clean :
	-rm -f *.o *.s core.* *~ wireshark

%.o : %.c
	$(CC) $(CFLAGS) $(DIR_LIBS) $(LIBS) $(INCLUDE) -c $<

testx: $(TEST_OBJS)
	$(CC) $^ $(CFLAGS) $(DIR_LIBS) $(LIBS) $(INCLUDE) -o $@
