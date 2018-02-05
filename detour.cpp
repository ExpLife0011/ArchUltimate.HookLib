#include "stdafx.h"
#include "hook.h"

EXTERN HStatus WINAPI HookDetour(CONST IN PDetourContext Context)
{
	DWORD ContinuedJumpSize;
	DWORD DetourMethodSize;
	HStatus Status = HOOK_NO_ERR;

	if (!Context->lpSource)
	{
		return HOOK_INVALID_SOURCE;
	}

	if (!Context->lpDestination)
	{
		return HOOK_INVALID_SOURCE;
	}

	if (Context->Flags == 0)
	{
		Context->Flags = Default;
	}

	if (Context->Flags & Reconstruct)
	{
		PBYTE originalData = (PBYTE) HookRecreateCode((PBYTE) Context->lpSource, 16);
#ifndef _WIN64
		DWORD instructionSize = HookAssertLength(originalData, 5);
#else
		DWORD instructionSize = HookAssertLength(originalData, 16);
#endif
		if (instructionSize)
		{
			WriteProcessMemory(GetCurrentProcess(),
				Context->lpSource,
				originalData,
				instructionSize,
				NULL);

			HookRelocateCode((PBYTE) Context->lpSource, instructionSize, (PBYTE) Context->lpSource);
		}
	}

#ifndef _WIN64

	DetourMethodSize = 5;
	ContinuedJumpSize = 5;

	Context->dwLength = HookAssertLength(Context->lpSource, 5);
	Context->Type = Relative;

#else

	ContinuedJumpSize = 16;
	Context->dwLength = HookAssertLength(Context->lpSource, 16);

	/* Check if the code area is not large enough to contain an absolute 16 byte jump. */
	if (!Context->dwLength)
	{
		/* Try a relative jump instead. */
		Context->dwLength = HookAssertLength(Context->lpSource, 6);
		if (Context->dwLength)
		{
			DetourMethodSize = 6;
			Context->Type = Relative;
		}
	}
	else
	{
		/* The code was large enough. */
		DetourMethodSize = 16;
		Context->Type = Absolute;
	}

#endif

	if (!Context->dwLength)
	{
		/* Invalid size. */
		return HOOK_NOT_ENOUGH_SPACE;
	}

	/* Recreate the original, and a jump back to the continued code. */
	if (Context->Flags & Recreate)
	{
		Context->pbReconstructed = (PBYTE) HookCreateCave(Context->lpSource, Context->dwLength + ContinuedJumpSize);
		if (!Context->pbReconstructed)
		{
			/* We failed creating the cave. */
			return HOOK_CAVE_FAILURE;
		}

		/* This is the chunk we took off from the source,
		we have to relocate it somewhere in case the caller wants to call this function. */

		/* Move the raw chunk. */
		memcpy(Context->pbReconstructed, Context->lpSource, Context->dwLength);
	}

	/* Check if user wanted a copy. */
	if (Context->Flags & SaveOriginal)
	{
		memcpy(Context->pbOriginal, Context->lpSource, Context->dwLength);
	}

	if (Context->Flags & Recreate)
	{
		/* Fix relocs in the chunk. */
		if ((Status = HookRelocateCode(Context->pbReconstructed, Context->dwLength, (PBYTE) Context->lpSource)) != HOOK_NO_ERR)
		{
			return Status;
		}

		if (Context->Flags & JumpOriginal)
		{
			/* Set the jump back to the continued code. */
			if (!SetJump((Context->pbReconstructed + Context->dwLength), (PBYTE) Context->lpSource + Context->dwLength))
			{
				return HOOK_PROTECTION_FAILURE;
			}
		}
	}

#ifdef _WIN64
	if (Context->Type == Relative)
	{
		/* Set a rip relative 6 byte jump. */
		if (!SetRelativeJump64((PBYTE) Context->lpSource, (PBYTE) Context->lpDestination))
		{
			return HOOK_PROTECTION_FAILURE;
		}
	}
	else
#endif
	{
		if (!SetJump((PBYTE) Context->lpSource, (PBYTE) Context->lpDestination))
		{
			return HOOK_PROTECTION_FAILURE;
		}


		DWORD Protection;
		if (VirtualProtect(Context->lpSource, Context->dwLength, PAGE_EXECUTE_READWRITE, &Protection))
		{
			for (DWORD i = DetourMethodSize; i < Context->dwLength; i++)
			{
				((PBYTE) (Context->lpSource))[i] = 0x90; /* nop */
			}

			VirtualProtect(Context->lpSource, Context->dwLength, Protection, &Protection);
		}
	}

	/* Update the instruction cache. */
	FlushInstructionCache(GetCurrentProcess(), Context->lpSource, Context->dwLength);

	return HOOK_NO_ERR;
}