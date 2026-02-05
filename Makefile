CC := clang
CFLAGS := -Wall -Wextra -std=c11
LD := lld
LDFLAGS := -fuse-ld=$(LD) -lZydis -lelf -lLLVM

SOURCES_PARSER = src/main.c src/vec.c

build_parser:
	$(CC) $(CFLAGS) $(SOURCES_PARSER) $(LDFLAGS)


