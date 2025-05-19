#include "aes.h"
#include <stdlib.h>
#include <stdio.h>
#include <ntstatus.h> // Prevent redefinition conflicts with ntstatus.h
#include <windows.h>  // Required for other Windows APIs
#include <bcrypt.h>   // Required for BCrypt functions

#pragma comment(lib, "Bcrypt.lib")

#define AES_KEY_SIZE  32
#define AES_IV_SIZE   16

/**
 * @brief Implementation of AES-CBC decryption with PKCS7 padding.
 */
bool aes_decrypt(const uint8_t* cipherData, size_t cipherSize,
    const uint8_t* key, const uint8_t* iv,
    uint8_t** plainData, size_t* plainSize)
{
    if (!cipherData || !key || !iv || !plainData || !plainSize) {
        fprintf(stderr, "aes_decrypt: invalid parameter\n");
        return false;
    }

    BCRYPT_ALG_HANDLE   hAlg = NULL;
    BCRYPT_KEY_HANDLE   hKey = NULL;
    NTSTATUS            status = STATUS_UNSUCCESSFUL;
    uint8_t* keyObject = NULL;
    ULONG               keyObjLen = 0;
    ULONG               resultLen = 0;
    uint8_t* output = NULL;
    ULONG               outputLen = 0;
    bool                success = false;

    // Open AES algorithm provider
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (status != 0) {
        fprintf(stderr, "BCryptOpenAlgorithmProvider failed: 0x%08x\n", status);
        goto Cleanup;
    }

    // Set CBC chaining mode
    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
        sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (status != 0) {
        fprintf(stderr, "BCryptSetProperty chaining mode failed: 0x%08x\n", status);
        goto Cleanup;
    }

    // Get object length for symmetric key
    status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
        (PUCHAR)&keyObjLen, sizeof(keyObjLen),
        &resultLen, 0);
    if (status != 0) {
        fprintf(stderr, "BCryptGetProperty object length failed: 0x%08x\n", status);
        goto Cleanup;
    }

    keyObject = (uint8_t*)HeapAlloc(GetProcessHeap(), 0, keyObjLen);
    if (!keyObject) {
        fprintf(stderr, "HeapAlloc for key object failed\n");
        goto Cleanup;
    }

    // Generate the symmetric key
    status = BCryptGenerateSymmetricKey(hAlg, &hKey, keyObject,
        keyObjLen, (PUCHAR)key,
        AES_KEY_SIZE, 0);
    if (status != 0) {
        fprintf(stderr, "BCryptGenerateSymmetricKey failed: 0x%08x\n", status);
        goto Cleanup;
    }

    // Determine required plaintext buffer size
    status = BCryptDecrypt(hKey,
        (PUCHAR)cipherData, (ULONG)cipherSize,
        NULL, (PUCHAR)iv, AES_IV_SIZE,
        NULL, 0, &outputLen,
        BCRYPT_BLOCK_PADDING);
    if (status != 0) {
        fprintf(stderr, "BCryptDecrypt(size) failed: 0x%08x\n", status);
        goto Cleanup;
    }

    output = (uint8_t*)HeapAlloc(GetProcessHeap(), 0, outputLen);
    if (!output) {
        fprintf(stderr, "HeapAlloc for output buffer failed\n");
        goto Cleanup;
    }

    // Perform decryption
    status = BCryptDecrypt(hKey,
        (PUCHAR)cipherData, (ULONG)cipherSize,
        NULL, (PUCHAR)iv, AES_IV_SIZE,
        output, outputLen, &resultLen,
        BCRYPT_BLOCK_PADDING);
    if (status != 0) {
        fprintf(stderr, "BCryptDecrypt failed: 0x%08x\n", status);
        goto Cleanup;
    }

    *plainData = output;
    *plainSize = resultLen;
    output = NULL; // ownership transferred
    success = true;

Cleanup:
    if (output) {
        HeapFree(GetProcessHeap(), 0, output);
    }
    if (hKey) {
        BCryptDestroyKey(hKey);
    }
    if (hAlg) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }
    if (keyObject) {
        HeapFree(GetProcessHeap(), 0, keyObject);
    }

    return success;
}