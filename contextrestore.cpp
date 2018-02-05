#include "stdafx.h"
#include "hook.h"

EXTERN HStatus WINAPI HookDetourContextRestore(CONST IN PDetourContext Context)
{
	DWORD dwProtection = PAGE_EXECUTE;
	SIZE_T NumberofBytesToProtect;
	PVOID Base = NULL;

	if (!Context->lpSource)
	{
		return HOOK_INVALID_SOURCE;
	}

	if (!Context->lpDestination)
	{
		return HOOK_INVALID_SOURCE;
	}

	if (!Context->dwLength)
	{
		return HOOK_INVALID_SIZE;
	}

	if (!Context->pbOriginal)
	{
		return HOOK_INVALID_RESTORATION;
	}

	Base = Context->lpSource;
	NumberofBytesToProtect = (SIZE_T) Context->dwLength;

	/* Give us access to the page. */
	if (!VirtualProtect(Context->lpSource, (SIZE_T) Context->dwLength, PAGE_EXECUTE_READWRITE, &dwProtection))
	{
		return HOOK_FAILED_API;
	}

	/* Do the restore. */
	memcpy(Context->lpSource, Context->pbOriginal, Context->dwLength);

	/* Restore access to the page. */
	VirtualProtect(Context->lpSource,
		(SIZE_T) Context->dwLength,
		dwProtection,
		&dwProtection);

	return HOOK_NO_ERR;
}