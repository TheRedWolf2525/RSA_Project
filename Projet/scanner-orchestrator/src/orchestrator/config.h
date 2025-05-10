#ifndef CONFIG_H
#define CONFIG_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char options[256];
    int enabled;
} ScannerConfig;

typedef struct {
    char address[256];
} TargetHost;

typedef struct {
    char address[256];
    int port;
} CommunicationConfig;

typedef struct {
    ScannerConfig scanners[3];
    TargetHost targets[10];
    CommunicationConfig communication;
    int scanner_count;
    int target_count;
    char **scanner_names;
    char **target_hosts;
} Config;

Config load_config();
void free_config(Config config);

ScannerConfig* get_scanner_configs();
TargetHost* get_target_hosts();
int get_number_of_scanners();
int get_number_of_targets();

#endif // CONFIG_H