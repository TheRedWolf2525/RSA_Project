#ifndef ORCHESTRATOR_H
#define ORCHESTRATOR_H

#include "config.h"

int orchestrator_init();

void orchestrator_run();

void orchestrator_cleanup();

Config load_config();

int execute_scan(const char* scanner_name, const char* target);

int get_agent_count();

#endif // ORCHESTRATOR_H