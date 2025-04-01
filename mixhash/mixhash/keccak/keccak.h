#ifndef KECCAK_H
#define KECCAK_H

#ifdef __cplusplus
extern "C" {
#endif

// #include <stdint.h>

void keccak_hash(const char* input, char* output, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif // KECCAK_H
