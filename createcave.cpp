#include "stdafx.h"
#include "hook.h"

EXTERN PVOID WINAPI HookCreateCave32(IN LPVOID lpBaseAddress, CONST IN SIZE_T Size)
{
	return VirtualAlloc(lpBaseAddress, Size,
		MEM_RESERVE | MEM_COMMIT,
		PAGE_EXECUTE_READWRITE);
}

EXTERN PVOID WINAPI HookCreateCave64(IN LPVOID lpBaseAddress, CONST IN SIZE_T Size)
{
	LPVOID lpAddress = NULL;
	MEMORY_BASIC_INFORMATION mbi = { 0 };

	for (PBYTE Addr = (PBYTE) lpBaseAddress; Addr > (PBYTE) lpBaseAddress - 0xffffffff / 2; Addr = (PBYTE) mbi.BaseAddress - 1)
	{
		if (!VirtualQuery((LPCVOID) Addr, &mbi, sizeof(mbi)))
		{
			break;
		}

		if (mbi.State != MEM_FREE)
		{
			continue;
		}

		lpAddress = VirtualAlloc(
			mbi.BaseAddress,
			Size,
			MEM_RESERVE | MEM_COMMIT,
			PAGE_EXECUTE_READWRITE);

		if (lpAddress)
		{
			break;
		}
	}

	return lpAddress;
}