# Telnet client/server over TCP (C, POSIX).
#   make            build bin/telnet-server and bin/telnet-client
#   make test       build and run unit tests
#   make DEBUG=1    -O0, -Werror, AddressSanitizer + UBSan
#   make clean

CC      ?= cc
CFLAGS  ?= -O2 -g
CFLAGS  += -std=gnu11 -D_GNU_SOURCE -Wall -Wextra -Wshadow -Iinclude -MMD -MP
LDLIBS  += -lutil

ifdef DEBUG
CFLAGS  += -O0 -g3 -Werror -fsanitize=address,undefined -fno-omit-frame-pointer
LDFLAGS += -fsanitize=address,undefined
endif

BUILD := build
BIN   := bin

COMMON_SRC := src/common/telnet_codec.c src/common/telnet_opts.c src/common/buffer.c \
              src/common/log.c src/common/net_util.c
SERVER_SRC := src/server/main.c src/server/config.c src/server/server.c src/server/session.c
CLIENT_SRC := src/client/main.c src/client/config.c src/client/client.c \
              src/client/terminal.c src/client/ui.c
TEST_SRC   := tests/test_codec.c tests/test_opts.c

obj = $(patsubst %.c,$(BUILD)/%.o,$(1))
COMMON_OBJ := $(call obj,$(COMMON_SRC))
SERVER_OBJ := $(call obj,$(SERVER_SRC))
CLIENT_OBJ := $(call obj,$(CLIENT_SRC))
TESTS      := $(patsubst tests/%.c,$(BIN)/%,$(TEST_SRC))

.PHONY: all test clean
all: $(BIN)/telnet-server $(BIN)/telnet-client

$(BIN)/telnet-server: $(SERVER_OBJ) $(COMMON_OBJ)
	@mkdir -p $(@D)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(BIN)/telnet-client: $(CLIENT_OBJ) $(COMMON_OBJ)
	@mkdir -p $(@D)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(BIN)/test_%: tests/test_%.c $(COMMON_OBJ)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(BUILD)/%.o: %.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c -o $@ $<

test: $(TESTS)
	@for t in $(TESTS); do ./$$t || exit 1; done

clean:
	rm -rf $(BUILD) $(BIN)

-include $(COMMON_OBJ:.o=.d) $(SERVER_OBJ:.o=.d) $(CLIENT_OBJ:.o=.d)
