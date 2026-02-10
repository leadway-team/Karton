ARCH := $(shell uname -m)
CC := clang
CFLAGS := -Wall -Wextra -std=c11
LD := lld
LDFLAGS := -fuse-ld=$(LD) -lZydis -lelf -lLLVM -ljson-c
DEBUG ?= 0

ifeq ($(ARCH), x86_64)
	CFLAGS += --target=aarch64-linux-gnu --sysroot=/usr/aarch64-linux-gnu
	LDFLAGS += --sysroot=/usr/aarch64-linux-gnu
endif

ifneq ($(DEBUG), 0)
	CFLAGS += -DDEBUG
endif

ifeq ($(DEBUG), 2)
	CFLAGS += -fsanitize=address -fno-omit-frame-pointer
endif

SOURCES = src/main.c src/karton.c src/vec.c

all: build

build:
	$(CC) $(CFLAGS) $(SOURCES) $(LDFLAGS)


