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
        snprintf(command, sizeof(command), "zap-cli quick-scan %s --url http://%s > %s 2>&1", 
                options, target, OUTPUT_FILE);
    } else {
        snprintf(command, sizeof(command), "zap-cli quick-scan --self-contained --url http://%s > %s 2>&1", 
                target, OUTPUT_FILE);
    }
    
    printf("Executing: %s\n", command);
    int ret = system(command);
    
    if (ret != 0) {
        printf("First ZAP command failed, trying alternative method...\n");
        snprintf(command, sizeof(command), "docker run -i owasp/zap2docker-stable zap-baseline.py -t http://%s > %s 2>&1", 
                target, OUTPUT_FILE);
        printf("Executing alternative: %s\n", command);
        ret = system(command);
    }
    
    return ret;
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
    fflush(stdout);
    
    char command[1024];
    char output_file[] = "/tmp/scanner_output.XXXXXX";
    int fd = mkstemp(output_file);
    if (fd == -1) {
        perror("Failed to create temporary file");
        fflush(stdout);
        send_results("Error: Failed to create temporary file");
        return -1;
    }
    close(fd);
    
    int result;
    if (strcasecmp(scanner_type, "nmap") == 0) {
        if (options) {
            snprintf(command, sizeof(command), "nmap %s %s > %s 2>&1", 
                     options, target, output_file);
        } else {
            snprintf(command, sizeof(command), "nmap %s > %s 2>&1", 
                     target, output_file);
        }
    } else if (strcasecmp(scanner_type, "zap") == 0) {
    int success = 0;
    
    if (!success) {
        snprintf(command, sizeof(command), "which zap-cli > /dev/null 2>&1");
        if (system(command) == 0) {
            printf("Using zap-cli for scanning\n");
            
            if (options) {
                snprintf(command, sizeof(command), "zap-cli quick-scan %s -t http://%s > %s 2>&1", 
                        options, target, output_file);
            } else {
                snprintf(command, sizeof(command), "zap-cli quick-scan -t http://%s > %s 2>&1", 
                        target, output_file);
            }
            
            if (system(command) == 0) {
                success = 1;
                printf("ZAP-CLI scan completed successfully\n");
            }
        }
    }
    
    if (!success) {
        printf("Trying ZAP via Docker...\n");
        snprintf(command, sizeof(command), "docker run -i owasp/zap2docker-stable zap-baseline.py -t http://%s > %s 2>&1", 
                 target, output_file);
        if (system(command) == 0) {
            success = 1;
            printf("ZAP Docker scan completed successfully\n");
        } else {
            FILE *output = fopen(output_file, "w");
            if (output) {
                fprintf(output, "ZAP Security Scanner\n");
                fprintf(output, "Target: http://%s\n\n", target);
                fprintf(output, "Error: Unable to run OWASP ZAP scanner.\n");
                fprintf(output, "Please ensure OWASP ZAP is installed or Docker is configured correctly.\n");
                fprintf(output, "You can install ZAP from: https://www.zaproxy.org/download/\n");
                fclose(output);
                success = 1;
            }
        }
    }
    
    result = success ? 0 : -1;
} else if (strcasecmp(scanner_type, "nikto") == 0) {
        snprintf(command, sizeof(command), "nikto -h %s %s > %s 2>&1", 
                 target, options ? options : "", output_file);
    } else {
        printf("Unknown scanner type: %s\n", scanner_type);
        fflush(stdout);
        send_results("Error: Unknown scanner type");
        unlink(output_file);
        return -1;
    }
    
    printf("Executing command: %s\n", command);
    fflush(stdout);
    result = system(command);
    printf("Command execution complete with status: %d\n", result);
    fflush(stdout);
    
    FILE *file = fopen(output_file, "r");
    if (file) {
        fseek(file, 0, SEEK_END);
        long file_size = ftell(file);
        fseek(file, 0, SEEK_SET);
        
        if (file_size > 0) {
            char *result_buffer = malloc(file_size + 1);
            if (result_buffer) {
                size_t bytes_read = fread(result_buffer, 1, file_size, file);
                result_buffer[bytes_read] = '\0';
                
                printf("Read %zu bytes from output file\n", bytes_read);
                fflush(stdout);
                send_results(result_buffer);
                
                free(result_buffer);
            } else {
                perror("Failed to allocate memory for scan results");
                fflush(stdout);
                send_results("Error: Failed to allocate memory for scan results");
            }
        } else {
            printf("Warning: Scan completed but output file is empty\n");
            fflush(stdout);
            send_results("Warning: Scan completed but output file is empty");
        }
        
        fclose(file);
    } else {
        perror("Failed to open output file");
        fflush(stdout);
        send_results("Error: Failed to open scan results file");
    }
    
    unlink(output_file);
    return result;
}