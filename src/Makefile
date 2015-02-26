PJBASE=./lib/pjproject

-include $(PJBASE)/build.mak

PROG    = ../bin/sipmodem
OBJS    = sipmodem.o modem.o sip.o serial.o lib/cfg2/lib/libcfg2.a lib/spandsp/src/.libs/libspandsp.a lib/libserialport/.libs/libserialport.a
CC      = $(APP_CC)
LDFLAGS = $(APP_LDFLAGS)
LDLIBS  = $(APP_LDLIBS)
CFLAGS  = $(APP_CFLAGS) -Ilib/spandsp/src -Ilib/cfg2/include -Ilib/libserialport

LDFLAGS+=-lpthread -lutil -lm

sipmodem: sipmodem.o modem.o sip.o serial.o
	make $(OBJS)
	$(CC) $(OBJS) -o $(PROG) $(CFLAGS) $(LDFLAGS) $(LDLIBS)

all: build-cfg2 build-libserialport build-spandsp build-pjproject sipmodem

build-cfg2:
	cd lib/cfg2 && $(MAKE)

build-libserialport:
	cd lib/libserialport && ./autogen.sh && ./configure && $(MAKE)

build-spandsp:
	cd lib/spandsp && ./configure && $(MAKE)
	
build-pjproject:
	cd lib/pjproject && ./configure && $(MAKE) dep && $(MAKE)

.c.o: 
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f $(PROG) *~ *.o


clean-all: clean
	cd lib/spandsp && $(MAKE) clean && \
	cd ../pjproject && $(MAKE) clean

