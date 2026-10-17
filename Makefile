# CC is left to make's default (cc), which is gcc on most Linux systems and
# clang on macOS. Override with: make CC=clang
#
# -MMD -MP write a .d file per object listing the headers it includes, so
# editing a header rebuilds every .c that depends on it.
CFLAGS = -O2 -Wall -Wextra -Werror -MMD -MP
LDLIBS = -lresolv

TARGET = exposureproof
SRC_DIR = src
BUILD_DIR = build

# make install copies the binary to $(DESTDIR)$(PREFIX)/bin.
PREFIX ?= /usr/local
BINDIR = $(PREFIX)/bin

SRCS = $(wildcard $(SRC_DIR)/*.c)
OBJS = $(SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)
DEPS = $(OBJS:.o=.d)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDLIBS)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR):
	mkdir -p $@

install: $(TARGET)
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 $(TARGET) $(DESTDIR)$(BINDIR)/$(TARGET)

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(TARGET)

clean:
	rm -rf $(BUILD_DIR) $(TARGET)

.PHONY: all install uninstall clean

-include $(DEPS)
