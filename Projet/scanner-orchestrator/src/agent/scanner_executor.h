#ifndef SCANNER_EXECUTOR_H
#define SCANNER_EXECUTOR_H

#include "agent.h"

int execute_nmap(const char *target, const char *options);

int execute_owasp_zap(const char *target, const char *options);

int execute_nikto(const char *target, const char *options);

int execute_scanner(const char *scanner_type, const char *target, const char *options);

#endif // SCANNER_EXECUTOR_H