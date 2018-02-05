#include "stdafx.h"
#include "hook.h"

BOOLEAN IsConditionalJump(const PBYTE InstructionBytes, const SHORT Size)
{
	if (Size < 1)
	{
		return FALSE;
	}

	if (InstructionBytes[0] == 0x0F)
	{
		if (InstructionBytes[1] >= 0x80 && InstructionBytes[1] <= 0x8F)
		{
			return TRUE;
		}
	}

	if (InstructionBytes[0] >= 0x70 && InstructionBytes[0] <= 0x7F)
	{
		return TRUE;
	}

	if (InstructionBytes[0] == 0xE3)
	{
		return TRUE;
	}

	return FALSE;
}

PBYTE GetRelativeDestination(PBYTE Source, PBYTE Destination, SIZE_T Size)
{
	return (Source < Destination) ? (PBYTE) (0 - (Source - Destination) - Size) : (PBYTE) (Destination - (Source + Size));
}

PBYTE GetClosestfreeSpace(PBYTE lpAddress, SIZE_T Size, SIZE_T MinimumSize, SIZE_T MaxLength)
{
	PBYTE freeSpace = NULL;
	MEMORY_BASIC_INFORMATION mbi = { 0 };

	for (PBYTE Addr = lpAddress + Size; Addr < (PBYTE) lpAddress + MaxLength + Size; Addr = Addr++)
	{
		/* Check the block */
		if (!VirtualQuery((LPCVOID) Addr, &mbi, sizeof(mbi)))
		{
			break;
		}

		if (mbi.State == MEM_FREE)
		{
			/* Try and allocate on this spot. */
			freeSpace = (PBYTE) VirtualAlloc((LPVOID) Addr,
				MinimumSize,
				MEM_RESERVE | MEM_COMMIT,
				PAGE_EXECUTE_READWRITE);

			if (freeSpace)
			{
				break;
			}
		}
	}

	return freeSpace;
}

BOOLEAN SetJump(PBYTE Source, PBYTE Destination)
{
	DWORD Protection = PAGE_EXECUTE;
	//
	// Set the protection to something we can use. 
	//
	if (VirtualProtect((LPVOID) Source, JMPSIZE, PAGE_EXECUTE_READWRITE, &Protection))
	{
#ifdef _WIN64
		//
		// push rax
		// mov rax [address]
		// xchg qword ptr ss:[rsp], rax
		// ret
		//
		BYTE detour[] = { 0x50, 0x48, 0xB8, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0x48, 0x87, 0x04, 0x24, 0xC3 };
		memcpy((PBYTE) Source, detour, sizeof(detour));
		*(PBYTE*) (Source + 3) = Destination;
#else
		/* jmp dword ptr [address] */
		*(BYTE*) Source = 0xE9;
		*(PBYTE*) (Source + 1) = GetRelativeDestination(Source, Destination, 5);
#endif

		//
		// Reset the protection //
		//
		if (VirtualProtect((LPVOID) Source, JMPSIZE, Protection, &Protection))
		{
			return TRUE;
		}
	}
	return FALSE;
}

BOOLEAN SetRelativeJump64(PBYTE Source, PBYTE Destination)
{
	DWORD Protection = PAGE_EXECUTE;

	/* Set the protection to something we can use. */
	if (VirtualProtect((LPVOID) Source, 6, PAGE_EXECUTE_READWRITE, &Protection))
	{
		*(WORD*) (Source) = 0x25ff;
		*(PBYTE*) (Source + 2) = GetRelativeDestination(Source, Destination, 6);

		/* Reset the protection */
		if (VirtualProtect((LPVOID) Source, 6, Protection, &Protection))
		{
			return TRUE;
		}
	}
	return FALSE;
}

VOID
RelocateExistingRelative(PBYTE InstructionAddress,
	PBYTE				Source,
	PBYTE				Destination,
	SIZE_T				Displacement,
	BYTE				Type,
	BYTE				Index)
{
	if (Type == 8)
	{
		*(BYTE*) (InstructionAddress + Index) = (BYTE) ((BYTE) Displacement - (Destination - Source));
	}
	else if (Type == 16)
	{
		*(WORD*) (InstructionAddress + Index) = (WORD) ((WORD) Displacement - (Destination - Source));
	}
	else if (Type == 32)
	{
		*(DWORD*) (InstructionAddress + Index) = (DWORD) ((DWORD) Displacement - (Destination - Source));
	}
}

VOID RelocateConditional(PBYTE lpAddress,
	BYTE						InstSize,
	DWORD						CodeSize,
	PBYTE						Source,
	PBYTE						Destination,
	const BYTE					Type,
	const BYTE					Index,
	PBYTE						Offset)
{
	ULONG_PTR estimatedOffset;
	PBYTE AbsoluteDestination = lpAddress + ((ULONG_PTR) Offset - (Destination - Source)) + InstSize;
	PBYTE freeSpace = GetClosestfreeSpace(Destination, CodeSize, JMPSIZE, 0x1000);

	if (!freeSpace)
	{
		return;
	}

	/* This will be accessed by our new conditional if the flags are met.
	It will lead to the original destination.
	*/
	if (!SetJump(freeSpace, AbsoluteDestination))
	{
		return;
	}

	/* Calculate the new offset of our conditional, this time to the location of our direct jump. */
	estimatedOffset = (ULONG_PTR) GetRelativeDestination(lpAddress, freeSpace, InstSize);

	/* Its assumed that the conditional offset is never in a place other than 1

	Example:

	jne 0x2e

	This would jump to the address coming after the jne instruction (jne 0x2e) + the offset of 0x2e.

	so lets say jne 0x2e is located at 0x4000
	we would jump to 0x4000 + 0x2 (size of the instruction) + 0x2e (the offset)
	*/
	if (Type == 8 && estimatedOffset <= 0xff)
	{
		*(BYTE*) (lpAddress + Index) = (BYTE) estimatedOffset;
	}
	else if (Type == 16 && estimatedOffset <= 0xffff)
	{
		*(WORD*) (lpAddress + Index) = (WORD) estimatedOffset;
	}
	else if (Type == 32 && estimatedOffset <= 0xffffffff)
	{
		*(DWORD*) (lpAddress + Index) = (DWORD) estimatedOffset;
	}
	else
	{
		free((LPVOID) freeSpace);
	}
}