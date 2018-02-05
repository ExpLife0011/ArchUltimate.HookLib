#include "stdafx.h"
#include "hook.h"

#include <stdio.h>

PIMAGE_DOS_HEADER WINAPI ImageGetDosHeader(CONST IN HMODULE lpModule)
{
	PIMAGE_DOS_HEADER pHeaderDOS = (PIMAGE_DOS_HEADER) lpModule;
	if (pHeaderDOS->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return NULL;
	}

	return pHeaderDOS;
}

PIMAGE_NT_HEADERS WINAPI ImageGetNtHeader(CONST IN HMODULE lpModule)
{
	PIMAGE_DOS_HEADER pHeaderDOS = ImageGetDosHeader(lpModule);
	if (!pHeaderDOS)
	{
		return NULL;
	}

	PIMAGE_NT_HEADERS pHeaderNT = (PIMAGE_NT_HEADERS) ((LPBYTE) lpModule + pHeaderDOS->e_lfanew);
	if (pHeaderNT->Signature != IMAGE_NT_SIGNATURE)
	{
		return NULL;
	}

	return pHeaderNT;
}

ULONG WINAPI ImageOffsetFromRVA(IN PIMAGE_NT_HEADERS pImageHeader, IN DWORD RVA)
{
	PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(pImageHeader);

	/* Search through all sections */
	for (unsigned i = 0, sections = pImageHeader->FileHeader.NumberOfSections; i < sections; i++, sectionHeader++)
	{
		/* Check if the section we hit is the one we need */
		if (sectionHeader->VirtualAddress <= RVA)
		{
			if ((sectionHeader->VirtualAddress + sectionHeader->Misc.VirtualSize) > RVA)
			{
				/* The section is good, calculate our offset */

				RVA -= sectionHeader->VirtualAddress;
				RVA += sectionHeader->PointerToRawData;

				return RVA;
			}
		}
	}

	return 0;
}

#define SUBTRACT_PTR_32(x, y) (ULONG) (ULONG_PTR) ((ULONG_PTR)(x) - (ULONG_PTR)(y));
ULONG WINAPI ImageVaToRva(IN HMODULE hModule, IN LPCVOID lpAddress)
{
	return SUBTRACT_PTR_32(lpAddress, hModule);
}

ULONG WINAPI FileOffsetByVirtualAddress(IN LPCVOID lpAddress)
{
	PIMAGE_NT_HEADERS pHeaderNT;
	MEMORY_BASIC_INFORMATION memInfo = { 0 };
	HMODULE hModule;

	/* Find the module that allocated the address */
	if (!VirtualQuery(lpAddress,
		&memInfo,
		sizeof(memInfo)))
	{
		return 0;
	}

	/* Take the module */
	hModule = (HMODULE) memInfo.AllocationBase;
	if (!hModule)
	{
		return 0;
	}

	pHeaderNT = ImageGetNtHeader(hModule);
	if (!pHeaderNT)
	{
		return 0;
	}

	return ImageOffsetFromRVA(pHeaderNT, ImageVaToRva(hModule, lpAddress));
}

DWORD WINAPI FileReadAddress(IN LPCVOID lpBaseAddress, OUT PBYTE lpBufferOut, CONST IN DWORD dwCountToRead)
{
	DWORD dwFileOffset;
	LPSTR lpModulePath = NULL;
	FILE* hFile = NULL;
	DWORD tBytesRead = 0;
	HMODULE hModule;
	MEMORY_BASIC_INFORMATION memInfo = { 0 };

	/* Find the module that allocated the address */
	if (!VirtualQuery(lpBaseAddress,
		&memInfo,
		sizeof(memInfo)))
	{
		goto done;
	}

	/* Take the module */
	hModule = (HMODULE) memInfo.AllocationBase;
	if (!hModule)
	{
		goto done;
	}

	/* Get the file offset */
	dwFileOffset = FileOffsetByVirtualAddress(lpBaseAddress);
	if (!dwFileOffset)
	{
		goto done;
	}

	/* Allocate for the path of the module */
	lpModulePath = (LPSTR) malloc(MAX_PATH * 2 + 1);
	if (!lpModulePath)
	{
		goto done;
	}

	/* Acquire path of targetted module. */
	if (!GetModuleFileNameA(hModule, lpModulePath, MAX_PATH))
	{
		goto done;
	}

	/* Open the file */
	fopen_s(&hFile, lpModulePath, "r");
	if (!hFile)
	{
		goto done;
	}

	/* Go to the offset */
	fseek(hFile, dwFileOffset, SEEK_SET);

	/* Read it */
	tBytesRead = fread(lpBufferOut, 1, dwCountToRead, hFile);
	if (tBytesRead != dwCountToRead)
	{
	}

done:
	if (lpModulePath)
	{
		free(lpModulePath);
	}

	if (hFile != INVALID_HANDLE_VALUE || hFile != NULL)
	{
		fclose(hFile);
	}

	return tBytesRead;
}