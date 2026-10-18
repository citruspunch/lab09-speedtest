CC ?= gcc
CFLAGS = -Wall -Wextra -O2 -g -Iinclude
SRCDIR = src
INCDIR = include
BUILDDIR = build

CLIENT_TARGET = $(BUILDDIR)/speedtest_client
SERVER_TARGET = $(BUILDDIR)/speedtest_server

CLIENT_SRCS = $(SRCDIR)/speedtest_client.c \
              $(SRCDIR)/checksum.c \
              $(SRCDIR)/ip_header.c \
              $(SRCDIR)/tcp_header.c \
              $(SRCDIR)/raw_socket.c \
              $(SRCDIR)/logger.c \
              $(SRCDIR)/ping.c

CLIENT_OBJS = $(patsubst $(SRCDIR)/%.c,$(BUILDDIR)/%.o,$(CLIENT_SRCS))

SERVER_SRCS = $(SRCDIR)/speedtest_server.c
SERVER_OBJS = $(BUILDDIR)/speedtest_server.o

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
    LDFLAGS += -lpcap
endif

all: $(CLIENT_TARGET) $(SERVER_TARGET)

$(CLIENT_TARGET): $(CLIENT_OBJS) | $(BUILDDIR)
	$(CC) $(CFLAGS) -o $@ $(CLIENT_OBJS) $(LDFLAGS)

$(SERVER_TARGET): $(SERVER_OBJS) | $(BUILDDIR)
	$(CC) $(CFLAGS) -o $@ $(SERVER_OBJS)

$(BUILDDIR)/%.o: $(SRCDIR)/%.c | $(BUILDDIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILDDIR):
	mkdir -p $(BUILDDIR)

clean:
	rm -rf $(BUILDDIR) *.pcap *.log lab09-speedtest.zip

zip: clean
	zip -r lab09-speedtest.zip Makefile README.md .gitignore run_speedtest.sh include src assets -x "*.DS_Store" "*__MACOSX*"

.PHONY: all clean zip
