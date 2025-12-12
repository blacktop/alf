/*
 * Persistent fuzzing harness for benchmark testing.
 * Runs in a loop, calling parse_buggy repeatedly with the same input.
 * Designed for ALF stop-hook benchmarking.
 *
 * Build:
 *   clang -g -O0 -o persistent_harness persistent_harness.c buggy_parser.c
 *
 * Usage:
 *   ./persistent_harness <input_file> [iterations]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

int parse_buggy(const uint8_t* data, size_t size);

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input_file> [iterations]\n", argv[0]);
        return 1;
    }

    const char* input_file = argv[1];
    int iterations = (argc > 2) ? atoi(argv[2]) : 10000;

    // Read input file
    FILE* f = fopen(input_file, "rb");
    if (!f) {
        perror("fopen");
        return 1;
    }

    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (file_size <= 0 || file_size > 1024 * 1024) {
        fprintf(stderr, "Invalid file size: %ld\n", file_size);
        fclose(f);
        return 1;
    }

    uint8_t* data = (uint8_t*)malloc(file_size);
    if (!data) {
        perror("malloc");
        fclose(f);
        return 1;
    }

    size_t bytes_read = fread(data, 1, file_size, f);
    fclose(f);

    if (bytes_read != (size_t)file_size) {
        fprintf(stderr, "Short read: %zu < %ld\n", bytes_read, file_size);
        free(data);
        return 1;
    }

    printf("[*] Running %d iterations with %zu byte input\n", iterations, bytes_read);

    // Main fuzzing loop - this is where we hook
    for (int i = 0; i < iterations; i++) {
        // HOOK POINT: parse_buggy is called here
        // The stop-hook mutates 'data' before each call
        parse_buggy(data, bytes_read);
    }

    printf("[*] Completed %d iterations\n", iterations);
    free(data);
    return 0;
}
