#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <json-c/json.h>

#define CONFIG_FILE "config/config.json"

static Config global_config;
static int config_loaded = 0;

Config load_config() {
    if (config_loaded) {
        return global_config;
    }
    
    memset(&global_config, 0, sizeof(Config));
    
    FILE *file = fopen(CONFIG_FILE, "r");
    if (!file) {
        perror("Failed to open config file");
        strcpy(global_config.communication.address, "0.0.0.0");
        global_config.communication.port = 8080;
        
        global_config.scanner_count = 3;
        global_config.scanner_names = malloc(global_config.scanner_count * sizeof(char*));
        global_config.scanner_names[0] = strdup("nmap");
        global_config.scanner_names[1] = strdup("zap");
        global_config.scanner_names[2] = strdup("nikto");
        
        global_config.target_count = 1;
        global_config.target_hosts = malloc(global_config.target_count * sizeof(char*));
        global_config.target_hosts[0] = strdup("localhost");
        
        printf("Using default configuration\n");
        config_loaded = 1;
        return global_config;
    }

    fseek(file, 0, SEEK_END);
    long length = ftell(file);
    fseek(file, 0, SEEK_SET);

    char *data = malloc(length + 1);
    if (!data) {
        perror("Failed to allocate memory for config data");
        fclose(file);
        exit(EXIT_FAILURE);
    }
    
    fread(data, 1, length, file);
    data[length] = '\0';
    fclose(file);

    struct json_object *parsed_json;
    struct json_object *scanners_obj;
    struct json_object *communication_obj;
    struct json_object *port_obj;

    parsed_json = json_tokener_parse(data);
    if (!parsed_json) {
        fprintf(stderr, "Failed to parse JSON config\n");
        free(data);
        strcpy(global_config.communication.address, "0.0.0.0");
        global_config.communication.port = 8080;
        config_loaded = 1;
        return global_config;
    }

    if (json_object_object_get_ex(parsed_json, "scanners", &scanners_obj)) {
        global_config.scanner_count = 0;
        
        json_object_object_foreach(scanners_obj, key1, val1) {
            global_config.scanner_count++;
        }
        
        global_config.scanner_names = malloc(global_config.scanner_count * sizeof(char *));
        if (!global_config.scanner_names) {
            perror("Failed to allocate memory for scanner names");
            free(data);
            json_object_put(parsed_json);
            exit(EXIT_FAILURE);
        }
        
        int i = 0;
        json_object_object_foreach(scanners_obj, key2, val2) {
            global_config.scanner_names[i] = strdup(key2);
            
            struct json_object *enabled_obj;
            if (json_object_object_get_ex(val2, "enabled", &enabled_obj)) {
                global_config.scanners[i].enabled = json_object_get_boolean(enabled_obj);
            } else {
                global_config.scanners[i].enabled = 1;
            }
            
            struct json_object *options_obj;
            if (json_object_object_get_ex(val2, "default_options", &options_obj)) {
                if (json_object_is_type(options_obj, json_type_string)) {
                    strncpy(global_config.scanners[i].options, 
                            json_object_get_string(options_obj), 
                            sizeof(global_config.scanners[i].options) - 1);
                    global_config.scanners[i].options[sizeof(global_config.scanners[i].options) - 1] = '\0';
                }
            }
            i++;
        }
    } else {
        global_config.scanner_count = 3;
        global_config.scanner_names = malloc(global_config.scanner_count * sizeof(char*));
        global_config.scanner_names[0] = strdup("nmap");
        global_config.scanner_names[1] = strdup("zap");
        global_config.scanner_names[2] = strdup("nikto");
    }

    global_config.target_count = 1;
    global_config.target_hosts = malloc(global_config.target_count * sizeof(char*));
    global_config.target_hosts[0] = strdup("localhost");
    strcpy(global_config.targets[0].address, "localhost");

    if (json_object_object_get_ex(parsed_json, "communication", &communication_obj)) {
        if (json_object_object_get_ex(communication_obj, "port", &port_obj)) {
            global_config.communication.port = json_object_get_int(port_obj);
        } else {
            global_config.communication.port = 8080;
        }
        
        strcpy(global_config.communication.address, "0.0.0.0");
    } else {
        strcpy(global_config.communication.address, "0.0.0.0");
        global_config.communication.port = 8080;
    }

    printf("Configuration loaded successfully:\n");
    printf("- %d scanner(s)\n", global_config.scanner_count);
    printf("- %d target(s)\n", global_config.target_count);
    printf("- Listening on %s:%d\n", global_config.communication.address, global_config.communication.port);

    free(data);
    json_object_put(parsed_json);
    
    config_loaded = 1;
    return global_config;
}

void free_config(Config config) {
    for (int i = 0; i < config.scanner_count; i++) {
        free(config.scanner_names[i]);
    }
    free(config.scanner_names);

    for (int i = 0; i < config.target_count; i++) {
        free(config.target_hosts[i]);
    }
    free(config.target_hosts);
    
    config_loaded = 0;
}

ScannerConfig* get_scanner_configs() {
    if (!config_loaded) {
        load_config();
    }
    return global_config.scanners;
}

TargetHost* get_target_hosts() {
    if (!config_loaded) {
        load_config();
    }
    return global_config.targets;
}

int get_number_of_scanners() {
    if (!config_loaded) {
        load_config();
    }
    return global_config.scanner_count;
}

int get_number_of_targets() {
    if (!config_loaded) {
        load_config();
    }
    return global_config.target_count;
}