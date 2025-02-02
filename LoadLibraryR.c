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
#include "LoadLibraryR.h"
#include <stdio.h>
#include <malloc.h>
#include "starfly.h"
#include "nt.h"
//===============================================================================================//

enum {
	PROC_WIN_UNKNOWN,
	PROC_WIN_X86,
	PROC_WIN_X64
};

/**
Copyright (c) 2006-2013, Rapid7 Inc

Redistribution and use in source and binary forms, with or without modification, are
permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this list of
conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice, this list of
conditions and the following disclaimer in the documentation and/or other materials
provided with the distribution.

* Neither the name of Rapid7 nor the names of its contributors may be used to endorse or
promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

typedef void (WINAPI * GETNATIVESYSTEMINFO)( LPSYSTEM_INFO lpSystemInfo );

// Definitions used for running native x64 code from a wow64 process (see executex64.asm)
typedef BOOL (WINAPI * X64FUNCTION)(DWORD dwParameter);
typedef DWORD(WINAPI * EXECUTEX64)(X64FUNCTION pFunction, DWORD dwParameter);

// see '/msf3/external/source/shellcode/x86/migrate/executex64.asm'
static BYTE migrate_executex64[] =	"\x55\x89\xE5\x56\x57\x8B\x75\x08\x8B\x4D\x0C\xE8\x00\x00\x00\x00"
									"\x58\x83\xC0\x25\x83\xEC\x08\x89\xE2\xC7\x42\x04\x33\x00\x00\x00"
									"\x89\x02\xE8\x09\x00\x00\x00\x83\xC4\x14\x5F\x5E\x5D\xC2\x08\x00"
									"\x8B\x3C\x24\xFF\x2A\x48\x31\xC0\x57\xFF\xD6\x5F\x50\xC7\x44\x24"
									"\x04\x23\x00\x00\x00\x89\x3C\x24\xFF\x2C\x24";


DWORD Rva2Offset( DWORD dwRva, UINT_PTR uiBaseAddress )
{    
	WORD wIndex                          = 0;
	WORD wNumberOfSections               = 0;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew);
		PIMAGE_NT_HEADERS64 pNtHeaders64 = (PIMAGE_NT_HEADERS64)pNtHeaders;
		pSectionHeader = (PIMAGE_SECTION_HEADER)((UINT_PTR)(&pNtHeaders64->OptionalHeader) + pNtHeaders64->FileHeader.SizeOfOptionalHeader);
		wNumberOfSections = pNtHeaders64->FileHeader.NumberOfSections;

    if( dwRva < pSectionHeader[0].PointerToRawData )
        return dwRva;

    for (wIndex = 0; wIndex < wNumberOfSections; wIndex++)
    {   
        if( dwRva >= pSectionHeader[wIndex].VirtualAddress && dwRva < (pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].SizeOfRawData) )           
           return ( dwRva - pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].PointerToRawData );
    }
    
    return 0;
}
//===============================================================================================//
DWORD GetReflectiveLoaderOffset( VOID * lpReflectiveDllBuffer )
{
	UINT_PTR uiBaseAddress   = 0;
	UINT_PTR uiExportDir     = 0;
	UINT_PTR uiNameArray     = 0;
	UINT_PTR uiAddressArray  = 0;
	UINT_PTR uiNameOrdinals  = 0;
	DWORD dwCounter          = 0;

	uiBaseAddress = (UINT_PTR)lpReflectiveDllBuffer;

	// get the File Offset of the modules NT Header
	uiExportDir = uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew;
	// uiNameArray = the address of the modules export directory entry
		uiNameArray = (UINT_PTR)&((PIMAGE_NT_HEADERS64)uiExportDir)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

	// get the File Offset of the export directory
	uiExportDir = uiBaseAddress + Rva2Offset( ((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress, uiBaseAddress );

	// get the File Offset for the array of name pointers
	uiNameArray = uiBaseAddress + Rva2Offset( ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->AddressOfNames, uiBaseAddress );

	// get the File Offset for the array of addresses
	uiAddressArray = uiBaseAddress + Rva2Offset( ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->AddressOfFunctions, uiBaseAddress );

	// get the File Offset for the array of name ordinals
	uiNameOrdinals = uiBaseAddress + Rva2Offset( ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->AddressOfNameOrdinals, uiBaseAddress );	

	// get a counter for the number of exported functions...
	dwCounter = ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->NumberOfNames;

	// loop through all the exported functions to find the ReflectiveLoader
	while( dwCounter-- )
	{
		char * cpExportedFunctionName = (char *)(uiBaseAddress + Rva2Offset( DEREF_32( uiNameArray ), uiBaseAddress ));

		if( strstr( cpExportedFunctionName, "ReflectiveLoader" ) != NULL )
		{
			// get the File Offset for the array of addresses
			uiAddressArray = uiBaseAddress + Rva2Offset( ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->AddressOfFunctions, uiBaseAddress );	
	
			// use the functions name ordinal as an index into the array of name pointers
			uiAddressArray += ( DEREF_16( uiNameOrdinals ) * sizeof(DWORD) );

			// return the File Offset to the ReflectiveLoader() functions code...
			return Rva2Offset( DEREF_32( uiAddressArray ), uiBaseAddress );
		}
		// get the next exported function name
		uiNameArray += sizeof(DWORD);

		// get the next exported function name ordinal
		uiNameOrdinals += sizeof(WORD);
	}

	return 0;
}
//===============================================================================================//
// Loads a DLL image from memory via its exported ReflectiveLoader function
HMODULE WINAPI LoadLibraryR( LPVOID lpBuffer, DWORD dwLength )
{
	HMODULE hResult                    = NULL;
	DWORD dwReflectiveLoaderOffset     = 0;
	DWORD dwOldProtect1                = 0;
	DWORD dwOldProtect2                = 0;
	REFLECTIVELOADER pReflectiveLoader = NULL;
	DLLMAIN pDllMain                   = NULL;

	if( lpBuffer == NULL || dwLength == 0 )
		return NULL;

	__try
	{
		// check if the library has a ReflectiveLoader...
		dwReflectiveLoaderOffset = GetReflectiveLoaderOffset( lpBuffer );
		if( dwReflectiveLoaderOffset != 0 )
		{
			pReflectiveLoader = (REFLECTIVELOADER)((UINT_PTR)lpBuffer + dwReflectiveLoaderOffset);

			// we must VirtualProtect the buffer to RWX so we can execute the ReflectiveLoader...
			// this assumes lpBuffer is the base address of the region of pages and dwLength the size of the region
			SIZE_T RegionSize = dwLength;
			DWORD OldProtect;
			SFNtProtectVirtualMemory(GetCurrentProcess(), &lpBuffer, &RegionSize, PAGE_EXECUTE_READWRITE, &OldProtect);
				// call the librarys ReflectiveLoader...
				pDllMain = (DLLMAIN)pReflectiveLoader();
				if( pDllMain != NULL )
				{
					// call the loaded librarys DllMain to get its HMODULE
					if( !pDllMain( NULL, DLL_QUERY_HMODULE, &hResult ) )	
						hResult = NULL;
				}
				// revert to the previous protection flags...
				RegionSize = dwLength;
				SFNtProtectVirtualMemory(GetCurrentProcess(), &lpBuffer, &RegionSize, OldProtect, &dwOldProtect2);
		}
	}
	__except( EXCEPTION_EXECUTE_HANDLER )
	{
		hResult = NULL;
	}
	return hResult;
}

static DWORD CreateBootstrap(
	LPBYTE lpBuffer,
	DWORD nBufferLen,
	DWORD dwTargetArch,
	ULONG_PTR uiParameter,
	ULONG_PTR uiLibraryAddress,
	DWORD dwFunctionHash,
	ULONG_PTR uiUserdataAddr,
	DWORD nUserdataLen,
	ULONG_PTR uiReflectiveLoaderAddr)
{
	DWORD i = 0;
	if (nBufferLen < 64)
		return 0;
			// mov rcx, <lpParameter>
			MoveMemory(lpBuffer + i, "\x48\xb9", 2);
			i += 2;
			MoveMemory(lpBuffer + i, &uiParameter, sizeof(uiParameter));
			i += sizeof(uiParameter);

			// mov rdx, <address of image base>
			MoveMemory(lpBuffer + i, "\x48\xba", 2);
			i += 2;
			MoveMemory(lpBuffer + i, &uiLibraryAddress, sizeof(uiLibraryAddress));
			i += sizeof(uiLibraryAddress);

			// mov r8d, <hash of function>
			MoveMemory(lpBuffer + i, "\x41\xb8", 2);
			i += 2;
			MoveMemory(lpBuffer + i, &dwFunctionHash, sizeof(dwFunctionHash));
			i += sizeof(dwFunctionHash);

			// mov r9, <address of userdata>
			MoveMemory(lpBuffer + i, "\x49\xb9", 2);
			i += 2;
			MoveMemory(lpBuffer + i, &uiUserdataAddr, sizeof(uiUserdataAddr));
			i += sizeof(uiUserdataAddr);

			// push <size of userdata>
			lpBuffer[i++] = 0x68; // PUSH (word/dword)
			MoveMemory(lpBuffer + i, &nUserdataLen, sizeof(nUserdataLen));
			i += sizeof(nUserdataLen);

			// sub rsp, 20
			MoveMemory(lpBuffer + i, "\x48\x83\xec\x20", 4);
			i += 4;

			// move rax, <address of reflective loader>
			MoveMemory(lpBuffer + i, "\x48\xb8", 2);
			i += 2;
			MoveMemory(lpBuffer + i, &uiReflectiveLoaderAddr, sizeof(uiReflectiveLoaderAddr));
			i += sizeof(uiReflectiveLoaderAddr);

		// call rax
		lpBuffer[i++] = 0xFF; // CALL
		lpBuffer[i++] = 0xD0; // RAX

	return i;
}
//===============================================================================================//
// Loads a PE image from memory into the address space of a host process via the image's exported ReflectiveLoader function
// Note: The hProcess handle must have these access rights: PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
//       PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ
// Note: If you are passing in an lpParameter value, if it is a pointer, remember it is for a different address space.
HANDLE WINAPI LoadRemoteLibraryR( 
	HANDLE hProcess, 
	LPVOID lpBuffer, 
	DWORD dwLength, 
	LPVOID lpParameter,
	DWORD dwFunctionHash,
	LPVOID lpUserdata, 
	DWORD nUserdataLen )
{
	HANDLE hThread		= NULL;
	DWORD dwThreadId	= 0;
	DWORD dwTargetArch	= PROC_WIN_X64;
	DWORD dwDllArch = PROC_WIN_X64;

	__try
	{
		do
		{
			SIZE_T bytesWritten;
			if (!hProcess || !lpBuffer || !dwLength)
				break;
			// check if the library has a ReflectiveLoader...
			DWORD dwReflectiveLoaderOffset = GetReflectiveLoaderOffset(lpBuffer);
			if (!dwReflectiveLoaderOffset)
				break;
			DWORD nBufferSize = dwLength
				+ nUserdataLen
				+ 64; // shellcode buffer

			// alloc memory (RWX) in the host process for the image...
			LPVOID lpRemoteLibraryBuffer = NULL;
			SIZE_T regionSize = nBufferSize;
			SFNtAllocateVirtualMemory(hProcess, &lpRemoteLibraryBuffer, 0, &regionSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			if (!lpRemoteLibraryBuffer)
				break;

			// write the image into the host process...
			SFNtWriteVirtualMemory(hProcess, lpRemoteLibraryBuffer, lpBuffer, dwLength, &bytesWritten);
			if (bytesWritten != dwLength)
				break;


			ULONG_PTR uiReflectiveLoaderAddr = (ULONG_PTR)lpRemoteLibraryBuffer + dwReflectiveLoaderOffset;

			// write our userdata blob into the host process
			ULONG_PTR userdataAddr = (ULONG_PTR)lpRemoteLibraryBuffer + dwLength;
			SFNtWriteVirtualMemory(hProcess, (LPVOID)userdataAddr, lpUserdata, nUserdataLen, &bytesWritten);
			if (bytesWritten != nUserdataLen)
				break;

			ULONG_PTR uiShellcodeAddr = userdataAddr + nUserdataLen;

			BYTE bootstrap[64] = { 0 };
			DWORD bootstrapLen = CreateBootstrap(
				bootstrap,
				64,
				dwTargetArch,
				(ULONG_PTR)lpParameter,
				(ULONG_PTR)lpRemoteLibraryBuffer,
				dwFunctionHash,
				userdataAddr,
				nUserdataLen,
				uiReflectiveLoaderAddr);
			if (bootstrapLen <= 0)
				break;

			// finally, write our shellcode into the host process
			SFNtWriteVirtualMemory(hProcess, (LPVOID)uiShellcodeAddr, bootstrap, bootstrapLen, &bytesWritten);
			if (bytesWritten != bootstrapLen)
				break;

			// Make sure our changes are written right away
			FlushInstructionCache(hProcess, lpRemoteLibraryBuffer, nBufferSize);
			HANDLE hThread = NULL;
			SFNtCreateThreadEx(
				&hThread,
				THREAD_ALL_ACCESS,
				NULL,
				hProcess,
				(LPTHREAD_START_ROUTINE)uiShellcodeAddr,
				lpParameter,
				FALSE,
				0,
				0,
				0,
				NULL);
		} while( 0 );

	}
	__except( EXCEPTION_EXECUTE_HANDLER )
	{
		hThread = NULL;
	}

	return hThread;
}
//===============================================================================================//
