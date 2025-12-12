#include <stdint.h>
#include <stdlib.h>
#include <plist/plist.h>

// Try binary first; fall back to XML. Exercise encode/decode paths.
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    plist_t p = NULL;
    plist_from_bin((const char*)data, (uint32_t)size, &p);
    if (!p) plist_from_xml((const char*)data, (uint32_t)size, &p);
    if (p) {
        char *out = NULL; uint32_t out_len = 0;
        plist_to_bin(p, &out, &out_len);
        free(out);
        out = NULL; out_len = 0;
        plist_to_xml(p, &out, &out_len);
        free(out);
        plist_free(p);
    }
    return 0;
}
