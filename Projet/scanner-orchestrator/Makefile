# Makefile

CC = gcc
CFLAGS = -Wall -Wextra -Iinclude -I./src/orchestrator -I./src/agent -I./src/common
LDFLAGS = -lssl -lcrypto -ljson-c

ORCHESTRATOR_SRC = src/orchestrator/main.c src/orchestrator/orchestrator.c src/orchestrator/config.c src/orchestrator/communication.c src/orchestrator/scanner_manager.c src/orchestrator/results_aggregator.c
AGENT_SRC = src/agent/main.c src/agent/agent.c src/agent/scanner_executor.c src/agent/communication.c
COMMON_SRC = src/common/crypto.c src/common/protocol.c src/common/utils.c

ORCHESTRATOR_OBJ = $(ORCHESTRATOR_SRC:.c=.o) $(COMMON_SRC:.c=.o)
AGENT_OBJ = $(AGENT_SRC:.c=.o) $(COMMON_SRC:.c=.o)

ORCHESTRATOR_BIN = orchestrator
AGENT_BIN = agent

all: $(ORCHESTRATOR_BIN) $(AGENT_BIN)

$(ORCHESTRATOR_BIN): $(ORCHESTRATOR_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(AGENT_BIN): $(AGENT_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(ORCHESTRATOR_OBJ) $(AGENT_OBJ) $(ORCHESTRATOR_BIN) $(AGENT_BIN)