#include "stdafx.h"
#include "hook.h"

EXTERN PVOID WINAPI HookRecreateCode(CONST IN PBYTE lpBaseAddress, CONST IN DWORD dwMinimumSize)
{
	PVOID Recreated;
	PBYTE Original;
	DWORD SizeOfFunction;
	DWORD dwRequiredSize;

	if (!lpBaseAddress)
	{
		return NULL;
	}

	dwRequiredSize = HookAssertLength(lpBaseAddress, dwMinimumSize);
	if (!dwRequiredSize)
	{
		/* Invalid function */
		return NULL;
	}

	/* Try obtaining the original bytecode. */
	Original = (PBYTE) malloc(dwRequiredSize);
	if (!Original)
	{
		return NULL;
	}

	if (!FileReadAddress(lpBaseAddress, Original, dwRequiredSize))
	{
		/* Leave the error to this function */
		free(Original);
		return NULL;
	}

	/* The size of our new function (block) */
	SizeOfFunction = dwRequiredSize + JMPSIZE;

	/* Allocate executable memory for our new function.
	In x86_64 its better to allocate near the original address, for rip relative jumps.
	*/
	Recreated = HookCreateCave(lpBaseAddress, SizeOfFunction);
	if (!Recreated)
	{
		/* We failed, the error is set by VirtualAlloc. */
		free(Original);
		return NULL;
	}

	/* Copy original block of function to our new function */
	memcpy(Recreated, Original, SizeOfFunction);

	/* Relocate the block we found. */
	if (HookRelocateCode((PBYTE) Recreated, SizeOfFunction, lpBaseAddress) != HOOK_NO_ERR)
	{
		free(Original);
		return FALSE;
	}

	/* free originally stored function bytes */
	free(Original);

	/* Write the jump. */
	if (!SetJump((PBYTE) Recreated + dwRequiredSize, (PBYTE) lpBaseAddress + dwRequiredSize))
	{
		return NULL;
	}
	return Recreated;
}