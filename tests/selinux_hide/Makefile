# Cross-compile the suite statically for the device.
#   make            -> ./sectest (aarch64 static)
#   make push       -> copy to /data/local/tmp (adb or a local shell helper)
CC      ?= aarch64-linux-gnu-gcc
CFLAGS  ?= -static -O2 -Wall
TARGET  ?= /data/local/tmp/sectest

sectest: sectest.c
	$(CC) $(CFLAGS) -o $@ $<

push: sectest
	cp sectest $(TARGET)
	chmod 755 $(TARGET)

clean:
	rm -f sectest

.PHONY: push clean
