#pragma once
#ifndef AES_H
#define AES_H

#include <windows.h>
#include <bcrypt.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

    /**
     * @brief Decrypt AES-encrypted data using CBC mode with PKCS7 padding.
     *
     * @param cipherData Pointer to the encrypted data buffer.
     * @param cipherSize Size of the encrypted data buffer in bytes.
     * @param key Pointer to the 32-byte AES key.
     * @param iv Pointer to the 16-byte initialization vector.
     * @param plainData Output pointer that will receive the allocated plaintext buffer. Caller must free this buffer via HeapFree.
     * @param plainSize Output variable that will receive the size of the plaintext buffer.
     * @return true on success, false on failure.
     */
    bool aes_decrypt(const uint8_t* cipherData, size_t cipherSize,
        const uint8_t* key, const uint8_t* iv,
        uint8_t** plainData, size_t* plainSize);

#ifdef __cplusplus
}
#endif

#endif // AES_H