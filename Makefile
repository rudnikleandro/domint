# CC is left to make's default (cc), which is gcc on most Linux systems and
# clang on macOS. Override with: make CC=clang
#
# -MMD -MP write a .d file per object listing the headers it includes, so
# editing a header rebuilds every .c that depends on it.
# C11 with POSIX.1-2008; _DEFAULT_SOURCE (glibc) and _DARWIN_C_SOURCE (macOS)
# add the BSD resolver API (res_ninit, ns_initparse) on each system.
CPPFLAGS = -Isrc -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE -D_DARWIN_C_SOURCE
CFLAGS = -std=c11 -O2 -Wall -Wextra -Werror -MMD -MP -pthread
LDLIBS = -lresolv -lcurl -pthread

TARGET = domint
SRC_DIR = src
BUILD_DIR = build

# make install copies the binary to $(DESTDIR)$(PREFIX)/bin.
PREFIX ?= /usr/local
BINDIR = $(PREFIX)/bin

# Sources live in one folder per layer: collect, core, output and support.
SRCS = $(wildcard $(SRC_DIR)/*.c $(SRC_DIR)/*/*.c)
OBJS = $(SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)
LIB_OBJS = $(filter-out $(BUILD_DIR)/main.o,$(OBJS))

# make test links every module except main.o with the files in tests/ and
# runs them from the project root, where tests/fixtures/ is found.
TEST_DIR = tests
TEST_SRCS = $(filter-out $(TEST_DIR)/fuzz.c,$(wildcard $(TEST_DIR)/*.c))
TEST_OBJS = $(TEST_SRCS:$(TEST_DIR)/%.c=$(BUILD_DIR)/tests/%.o)
TEST_BIN = $(BUILD_DIR)/run_tests

DEPS = $(OBJS:.o=.d) $(TEST_OBJS:.o=.d)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDLIBS)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

test: $(TEST_BIN)
	./$(TEST_BIN)

$(TEST_BIN): $(LIB_OBJS) $(TEST_OBJS)
	$(CC) $^ -o $@ $(LDLIBS)

$(BUILD_DIR)/tests/%.o: $(TEST_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

# make fuzz builds the parsers and report writers with ASan and UBSan and
# feeds them corrupted inputs; FUZZ_RUNS sets the inputs per target.
FUZZ_BIN = $(BUILD_DIR)/fuzz
FUZZ_FLAGS = -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=undefined -fno-omit-frame-pointer
FUZZ_RUNS ?= 20000

fuzz:
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) -std=c11 -Wall -Wextra -Werror -pthread $(FUZZ_FLAGS) $(filter-out $(SRC_DIR)/main.c,$(SRCS)) \
		$(TEST_DIR)/fuzz.c -o $(FUZZ_BIN) $(LDLIBS) $(FUZZ_FLAGS)
	./$(FUZZ_BIN) $(FUZZ_RUNS)

install: $(TARGET)
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 $(TARGET) $(DESTDIR)$(BINDIR)/$(TARGET)

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(TARGET)

clean:
	rm -rf $(BUILD_DIR) $(TARGET)

.PHONY: all test fuzz install uninstall clean

-include $(DEPS)
