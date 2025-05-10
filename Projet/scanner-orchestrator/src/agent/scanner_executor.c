#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "scanner_executor.h"

#define BUFFER_SIZE 4096
#define OUTPUT_FILE "/tmp/scanner_output.txt"

int execute_nmap(const char *target, const char *options) {
    char command[BUFFER_SIZE];
    
    if (options && strlen(options) > 0) {
        snprintf(command, sizeof(command), "nmap %s %s > %s 2>&1", options, target, OUTPUT_FILE);
    } else {
        snprintf(command, sizeof(command), "nmap -sV %s > %s 2>&1", target, OUTPUT_FILE);
    }
    
    printf("Executing: %s\n", command);
    return system(command);
}

int execute_owasp_zap(const char *target, const char *options) {
    char command[BUFFER_SIZE];
    
    if (options && strlen(options) > 0) {
        snprintf(command, sizeof(command), "zap-cli quick-scan %s --url %s > %s 2>&1", 
                options, target, OUTPUT_FILE);
    } else {
        snprintf(command, sizeof(command), "zap-cli quick-scan --self-contained --url %s > %s 2>&1", 
                target, OUTPUT_FILE);
    }
    
    printf("Executing: %s\n", command);
    return system(command);
}

int execute_nikto(const char *target, const char *options) {
    char command[BUFFER_SIZE];
    
    if (options && strlen(options) > 0) {
        snprintf(command, sizeof(command), "nikto %s -h %s > %s 2>&1", options, target, OUTPUT_FILE);
    } else {
        snprintf(command, sizeof(command), "nikto -h %s > %s 2>&1", target, OUTPUT_FILE);
    }
    
    printf("Executing: %s\n", command);
    return system(command);
}

int execute_scanner(const char *scanner_type, const char *target, const char *options) {
    printf("Executing scanner: %s on target: %s with options: %s\n", 
           scanner_type, target, options ? options : "none");
    
    if (strcasecmp(scanner_type, "nmap") == 0) {
        return execute_nmap(target, options);
    } else if (strcasecmp(scanner_type, "zap") == 0) {
        return execute_owasp_zap(target, options);
    } else if (strcasecmp(scanner_type, "nikto") == 0) {
        return execute_nikto(target, options);
    } else {
        printf("Unknown scanner type: '%s'\n", scanner_type);
        return -1;
    }
}