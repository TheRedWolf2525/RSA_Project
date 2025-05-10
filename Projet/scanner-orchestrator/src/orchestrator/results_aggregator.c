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