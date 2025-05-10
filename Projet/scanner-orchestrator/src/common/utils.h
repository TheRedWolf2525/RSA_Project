#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void log_message(const char *message, const char *log_file);

void* safe_malloc(size_t size);

void safe_free(void **ptr);

char* to_lowercase(const char *str);

char* trim_whitespace(char* str);

char* read_file(const char* filename);

#endif // UTILS_H