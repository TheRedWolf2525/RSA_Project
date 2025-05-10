#ifndef SCANNER_MANAGER_H
#define SCANNER_MANAGER_H

#include "config.h"

void init_scanner_manager();

int configure_scanner(const char* scanner_name);

int execute_scan(const char* scanner_name, const char* target);

int get_scan_results(const char* scanner_name, char** results);

void cleanup_scanner_manager();

#endif // SCANNER_MANAGER_H