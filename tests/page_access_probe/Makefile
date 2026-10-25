CC      ?= cc
TARGET  ?= page_access_probe
CFLAGS  ?= -O2 -Wall -Wextra -g
LDFLAGS ?=
# Static by default: the binary is meant to be pushed to a device and run under
# adb shell, where the host's glibc loader path does not exist.
STATIC  ?= 1

ifeq ($(STATIC),1)
LDFLAGS += -static
endif

all: $(TARGET)

$(TARGET): page_access_probe.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: all clean
