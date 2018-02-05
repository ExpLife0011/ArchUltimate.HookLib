#pragma once
#include "stdafx.h"

PIMAGE_DOS_HEADER WINAPI ImageGetDosHeader(CONST IN HMODULE lpModule);
PIMAGE_NT_HEADERS WINAPI ImageGetNtHeader(CONST IN HMODULE lpModule);
ULONG WINAPI ImageOffsetFromRVA(IN PIMAGE_NT_HEADERS pImageHeader, IN DWORD RVA);
ULONG WINAPI ImageVaToRva(IN HMODULE hModule, IN LPCVOID lpAddress);
ULONG WINAPI FileOffsetByVirtualAddress(IN LPCVOID lpAddress);
DWORD WINAPI FileReadAddress(IN LPCVOID lpBaseAddress, OUT PBYTE lpBufferOut, CONST IN DWORD dwCountToRead);