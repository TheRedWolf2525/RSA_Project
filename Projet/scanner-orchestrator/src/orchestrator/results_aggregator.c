#include "results_aggregator.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_RESULTS 100

typedef struct {
    char *scanner_name;
    char *result;
} ScanResult;

static ScanResult results[MAX_RESULTS];
static int result_count = 0;

void init_results_aggregator() {
    printf("Initializing results aggregator...\n");
    result_count = 0;
}

void aggregate_results(const char *scanner_name, const char *results_text) {
    if (result_count < MAX_RESULTS) {
        results[result_count].scanner_name = strdup(scanner_name);
        results[result_count].result = strdup(results_text);
        result_count++;
        printf("Result from %s added to aggregator\n", scanner_name);
    } else {
        fprintf(stderr, "Result storage full, cannot add more results.\n");
    }
}

void get_aggregated_summary() {
    printf("Aggregated Scan Results Summary:\n");
    printf("---------------------------------\n");
    for (int i = 0; i < result_count; i++) {
        printf("Scanner: %s\n", results[i].scanner_name);
        printf("Results: %s\n", results[i].result);
        printf("---------------------------------\n");
    }
}

void free_results_aggregator() {
    printf("Freeing results aggregator resources...\n");
    for (int i = 0; i < result_count; i++) {
        free(results[i].scanner_name);
        free(results[i].result);
    }
    result_count = 0;
}

void save_results_to_file() {
    FILE *file = fopen("scan_results.txt", "w");
    if (file == NULL) {
        fprintf(stderr, "Error: Could not open file for writing results\n");
        return;
    }
    
    fprintf(file, "==========================================\n");
    fprintf(file, "      SECURITY SCAN RESULTS SUMMARY      \n");
    fprintf(file, "==========================================\n\n");
    
    printf("Saving %d scan results to file\n", result_count);
    for (int i = 0; i < result_count; i++) {
        printf("Writing result %d: %s (length: %lu)\n", i, 
               results[i].scanner_name, 
               results[i].result ? strlen(results[i].result) : 0);
        
        fprintf(file, "Scanner: %s\n", results[i].scanner_name);
        fprintf(file, "-------------------------------------------\n");
        fprintf(file, "%s\n\n", results[i].result ? results[i].result : "No results available");
        fprintf(file, "-------------------------------------------\n\n");
    }
    
    fclose(file);
    printf("Results saved to scan_results.txt\n");
}

void add_scan_result(const char *scanner_name, const char *result) {
    if (result_count >= MAX_RESULTS) {
        fprintf(stderr, "Error: Maximum number of results reached\n");
        return;
    }
    
    printf("Adding result for scanner: %s\n", scanner_name);
    
    strncpy(results[result_count].scanner_name, scanner_name, sizeof(results[result_count].scanner_name) - 1);
    results[result_count].scanner_name[sizeof(results[result_count].scanner_name) - 1] = '\0';
    
    results[result_count].result = strdup(result);
    if (results[result_count].result == NULL) {
        fprintf(stderr, "Error: Failed to allocate memory for result\n");
        return;
    }
    
    result_count++;
    printf("Result added successfully. Total results: %d\n", result_count);
}