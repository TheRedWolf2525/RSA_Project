CC = gcc
CFLAGS = -Wall -Wextra -Werror -I../../include
LDFLAGS =

SRC = main.c orchestrateur.c
OBJ = $(SRC:.c=.o)
EXEC = orchestrateur

all: $(EXEC)

$(EXEC): $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) -o $@ -c $< $(CFLAGS)

clean:
	rm -f $(OBJ) $(EXEC)

.PHONY: all clean