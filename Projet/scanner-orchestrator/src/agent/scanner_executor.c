#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "scanner_executor.h"

#define BUFFER_SIZE 4096

int execute_nmap(const char *target, const char *options) {
    char output_file[] = "/tmp/nmap_output.XXXXXX";
    int fd = mkstemp(output_file);
    if (fd == -1) {
        perror("mkstemp for nmap failed");
        return -1;
    }
    close(fd);

    char command[BUFFER_SIZE];
    if (options && strlen(options) > 0) {
        snprintf(command, sizeof(command), "nmap %s %s > %s 2>&1", options, target, output_file);
    } else {
        snprintf(command, sizeof(command), "nmap -sV %s > %s 2>&1", target, output_file);
    }
    
    printf("Executing: %s\n", command);
    int result = system(command);

    unlink(output_file);
    return result;
}

int execute_owasp_zap(const char *target, const char *options) {
    char output_file[] = "/tmp/zap_output.XXXXXX";
    int fd = mkstemp(output_file);
    if (fd == -1) {
        perror("mkstemp for owasp_zap failed");
        return -1;
    }
    close(fd);

    char command[BUFFER_SIZE];
    if (options && strlen(options) > 0) {
        snprintf(command, sizeof(command), "zap-cli quick-scan %s --url %s > %s 2>&1", 
                options, target, output_file);
    } else {
        snprintf(command, sizeof(command), "zap-cli quick-scan --self-contained --url %s > %s 2>&1", 
                target, output_file);
    }
    
    printf("Executing: %s\n", command);
    int result = system(command);

    unlink(output_file);
    return result;
}

int execute_nikto(const char *target, const char *options) {
    char output_file[] = "/tmp/nikto_output.XXXXXX";
    int fd = mkstemp(output_file);
    if (fd == -1) {
        perror("mkstemp for nikto failed");
        return -1;
    }
    close(fd);

    char command[BUFFER_SIZE];
    if (options && strlen(options) > 0) {
        snprintf(command, sizeof(command), "nikto %s -h %s > %s 2>&1", options, target, output_file);
    } else {
        snprintf(command, sizeof(command), "nikto -h %s > %s 2>&1", target, output_file);
    }
    
    printf("Executing: %s\n", command);
    int result = system(command);

    unlink(output_file);
    return result;
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
        snprintf(command, sizeof(command), "zap -cmd -quickurl http://%s %s > %s 2>&1", 
                 target, options ? options : "", output_file);
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