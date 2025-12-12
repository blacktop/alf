// Intentional bugs for demo: off-by-one + divide-by-zero
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int parse_buggy(const uint8_t* data, size_t size) {
    if (size >= 8 && memcmp(data, "BPLIST10", 8) == 0) {
        uint32_t len = (size > 12) ? ((uint32_t)data[8] << 24) | ((uint32_t)data[9] << 16) |
                                    ((uint32_t)data[10] << 8) | (uint32_t)data[11] : 0;
        if (len > 0 && len < (1u << 20)) {
            uint8_t* buf = (uint8_t*)malloc(len);
            if (!buf) return 0;
            memcpy(buf, data + 12, len + 1); // BUG: off-by-one write
            free(buf);
        }
    }
    if (size >= 5 && data[0]=='C' && data[1]=='R' && data[2]=='S' && data[3]=='H') {
        volatile int z = (int)data[4] - 'A';
        volatile int x = 1 / (z == 0 ? 0 : z); // UBSan: integer divide by zero
        (void)x;
    }
    return 0;
}
