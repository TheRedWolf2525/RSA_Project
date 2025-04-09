CC = gcc
CFLAGS = -Wall -Wextra -I./include
LDFLAGS = -lssl -lcrypto

COMMON_SRC = src/common/protocol.c src/common/crypto.c
COMMON_OBJ = $(COMMON_SRC:.c=.o)

ORCHESTRATEUR_SRC = src/orchestrateur/main.c src/orchestrateur/orchestrateur.c
ORCHESTRATEUR_OBJ = $(ORCHESTRATEUR_SRC:.c=.o)

TEST_SRC = tests/test_crypto.c
TEST_OBJ = $(TEST_SRC:.c=.o)

all: check_openssl orchestrateur test_crypto

check_openssl:
	@echo "Checking for OpenSSL..."
	@if pkg-config --exists openssl; then \
        echo "OpenSSL found, enabling secure features"; \
        echo "#define HAVE_OPENSSL 1" > include/openssl_config.h; \
        $(eval CFLAGS += -DHAVE_OPENSSL=1 $(shell pkg-config --cflags openssl)); \
        $(eval LDFLAGS += $(shell pkg-config --libs openssl)); \
    else \
        echo "WARNING: OpenSSL not found, using fallback implementation"; \
        echo "#define HAVE_OPENSSL 0" > include/openssl_config.h; \
    fi

orchestrateur: $(ORCHESTRATEUR_OBJ) $(COMMON_OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

test_crypto: $(TEST_OBJ) $(COMMON_OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) -o $@ -c $< $(CFLAGS)

clean:
	rm -f $(ORCHESTRATEUR_OBJ) $(COMMON_OBJ) $(TEST_OBJ) orchestrateur test_crypto include/openssl_config.h

.PHONY: all clean check_openssl