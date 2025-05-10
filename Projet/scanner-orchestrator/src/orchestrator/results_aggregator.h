#ifndef RESULTS_AGGREGATOR_H
#define RESULTS_AGGREGATOR_H

#include "scanner_manager.h"

typedef struct {
    char *scanner_name;
    char *results;
} AggregatedResult;

void init_results_aggregator();

void aggregate_results(const char *scanner_name, const char *results);

void get_aggregated_summary();

void save_results_to_file();

void free_results_aggregator();

#endif // RESULTS_AGGREGATOR_H