#include <stdint.h>
#include <stddef.h>  // for size_t in the fuzz entry point
int parse_buggy(const uint8_t*, size_t);
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    parse_buggy(data, size);
    return 0;
}
