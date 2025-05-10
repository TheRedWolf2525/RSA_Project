#ifndef AGENT_H
#define AGENT_H

#include "communication.h"
#include "scanner_executor.h"

void initialize_agent();

void start_command_listener();

void handle_command(const char* command);

void send_results(const char* results);

#endif // AGENT_H