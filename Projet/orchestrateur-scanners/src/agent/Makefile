CC = gcc
CFLAGS = -Wall -Wextra -Werror -Wno-deprecated-declarations -Wno-unused-function -I../../include
LDFLAGS = -lssl -lcrypto

SRC = main.c agent.c
OBJ = $(SRC:.c=.o)
COMMON_SRC = ../common/protocol.c ../common/crypto.c
COMMON_OBJ = $(COMMON_SRC:.c=.o)
EXEC = agent

all: $(EXEC)

$(EXEC): $(OBJ) $(COMMON_OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $<

clean:
	rm -f $(OBJ) $(COMMON_OBJ) $(EXEC)