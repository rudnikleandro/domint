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

# make test links every module except main.o with the files in tests/ and
# runs them from the project root, where tests/fixtures/ is found.
TEST_DIR = tests
TEST_SRCS = $(wildcard $(TEST_DIR)/*.c)
TEST_OBJS = $(TEST_SRCS:$(TEST_DIR)/%.c=$(BUILD_DIR)/tests/%.o)
TEST_BIN = $(BUILD_DIR)/run_tests

DEPS = $(OBJS:.o=.d) $(TEST_OBJS:.o=.d)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDLIBS)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR) $(BUILD_DIR)/tests:
	mkdir -p $@

test: $(TEST_BIN)
	./$(TEST_BIN)

$(TEST_BIN): $(filter-out $(BUILD_DIR)/main.o,$(OBJS)) $(TEST_OBJS)
	$(CC) $^ -o $@ $(LDLIBS)

$(BUILD_DIR)/tests/%.o: $(TEST_DIR)/%.c | $(BUILD_DIR)/tests
	$(CC) $(CFLAGS) -I$(SRC_DIR) -c $< -o $@

install: $(TARGET)
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 $(TARGET) $(DESTDIR)$(BINDIR)/$(TARGET)

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(TARGET)

clean:
	rm -rf $(BUILD_DIR) $(TARGET)

.PHONY: all test install uninstall clean

-include $(DEPS)
