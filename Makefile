# Variables
CC = gcc
CFLAGS = -Wall -Wextra -Werror
SRC = $(wildcard *.c)
OBJ_DIR = obj
OBJ = $(patsubst %.c,$(OBJ_DIR)/%.o,$(SRC))
EXEC = program

# Création du répertoire des objets
$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

# Règle principale
tout: $(EXEC)

# Compilation de l'exécutable
$(EXEC): $(OBJ)
	$(CC) $(CFLAGS) $^ -o $@

# Compilation des fichiers objets
$(OBJ_DIR)/%.o: %.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Exécution du programme
run: $(EXEC)
	./$(EXEC)

# Nettoyage des fichiers objets et de l'exécutable
clean:
	rm -rf $(OBJ_DIR) $(EXEC)

# Nettoyage total
fclean: clean

# Recompilation complète
re: fclean tout