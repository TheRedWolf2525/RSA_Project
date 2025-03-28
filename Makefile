CC = gcc
CFLAGS = -Wall -Wextra -O2
SRC = $(wildcard *.c)
BIN_DIR = bin
BIN = $(patsubst %.c,$(BIN_DIR)/%,$(SRC))

all: $(BIN_DIR) $(BIN)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(BIN_DIR)/%: %.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -rf $(BIN_DIR)

rebuild: clean all

.PHONY: all clean rebuild
