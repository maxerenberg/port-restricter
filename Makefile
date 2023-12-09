CC ?= gcc
CFLAGS += -Wall -Wextra -Wconversion -Werror -std=gnu17 \
	  -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 \
	  $(shell pkg-config --cflags libseccomp)
LDFLAGS += $(shell pkg-config --libs libseccomp)
BIN = port-restricter
OBJS = port-restricter.o

.PHONY: clean

$(BIN): $(OBJS)
	$(CC) -o $@ $(OBJS) $(LDFLAGS)

clean:
	$(RM) $(BIN) $(OBJS)
