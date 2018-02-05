#pragma once
#include "stdafx.h"
#include "distorm/include/distorm.h"
#include "file.h"

typedef long HStatus;

#define HOOK_NO_ERR					(HStatus)0x0000
#define HOOK_INVALID_SOURCE			(HStatus)0x0001
#define HOOK_INVALID_DESTINATION	(HStatus)0x0002
#define HOOK_NOT_ENOUGH_SPACE		(HStatus)0x0003
#define HOOK_CAVE_FAILURE			(HStatus)0x0004
#define HOOK_INVALID_SIZE			(HStatus)0x0005
#define HOOK_FAILED_API				(HStatus)0x0006
#define HOOK_PROTECTION_FAILURE		(HStatus)0x0007
#define HOOK_INVALID_RESTORATION	(HStatus)0x0008

#ifndef _WIN64
#define HookCreateCave(x, y) HookCreateCave32(0, y);
#else
#define HookCreateCave(x, y) HookCreateCave64(x, y);
#endif

#define MAX_INSTRUCTIONS 0x100
#define OPCODE_INSTRUCTION_NOP (0x90)

#ifndef _WIN64
#define JMPSIZE 5
#else
#define JMPSIZE 16
#endif

typedef enum _DetourType {
	Relative = 1,
	Absolute = 2
} DetourType;

typedef enum _DetourFlags {
	Recreate = (1 << 0),
	Single = (1 << 1),
	SaveOriginal = (1 << 2),
	JumpOriginal = (1 << 3),
	Reconstruct = (1 << 4),
	Default = ((int) Recreate | JumpOriginal | SaveOriginal),
} DetourFlags;

typedef struct _DetourContext {
	/*
	--	*Required IN.
	--	Where it will be originated from.
	*/
	LPVOID lpSource;

	/*
	--	*Required IN.
	--	Where this hook will lead to.
	*/
	LPVOID lpDestination;

	/*
	--	OUT.
	--	Length of the detour.
	*/
	DWORD dwLength;

	/*
	--	OUT.
	--	Original function pointer.
	-- ** Contains relocation fixes.
	*/
	PBYTE pbReconstructed;

	/*
	--	OUT.
	--	Original function bytes;
	*/
	PBYTE pbOriginal;

	/*
	--	OUT.
	--	Hook type. [Relative/Absolute]
	*/
	DetourType Type;

	//
	// IN
	//
	DetourFlags Flags;

} DetourContext, *PDetourContext;

#ifdef _WINDLL

#ifdef __cplusplus
#define EXTERN extern "C" __declspec(dllexport)
#else
#define EXTERN extern __declspec(dllexport)
#endif // CPP

#else
#define EXTERN /* no linkage */
#endif

EXTERN HStatus WINAPI HookDetour(CONST IN PDetourContext Context);
EXTERN HStatus WINAPI HookDetourContextRestore(CONST IN PDetourContext Context);
EXTERN HStatus WINAPI HookRelocateCode(CONST IN PBYTE Code, IN DWORD Size, CONST IN PBYTE Source);
EXTERN PVOID WINAPI HookCreateCave32(IN LPVOID lpBaseAddress, CONST IN SIZE_T Size);
EXTERN PVOID WINAPI HookCreateCave64(IN LPVOID lpBaseAddress, CONST IN SIZE_T Size);
EXTERN DWORD WINAPI HookAssertLength(IN LPCVOID lpBaseAddress, CONST IN DWORD MinimumLength);
EXTERN PVOID WINAPI HookRecreateCode(CONST IN PBYTE lpBaseAddress, CONST IN DWORD dwMinimumSize);

BOOLEAN IsConditionalJump(const PBYTE InstructionBytes, const SHORT Size);
PBYTE GetRelativeDestination(PBYTE Source, PBYTE Destination, SIZE_T Size);
PBYTE GetClosestfreeSpace(PBYTE lpAddress, SIZE_T Size, SIZE_T MinimumSize, SIZE_T MaxLength);
BOOLEAN SetJump(PBYTE Source, PBYTE Destination);
BOOLEAN SetRelativeJump64(PBYTE Source, PBYTE Destination);

VOID
RelocateExistingRelative(PBYTE InstructionAddress,
	PBYTE				Source,
	PBYTE				Destination,
	SIZE_T				Displacement,
	BYTE				Type,
	BYTE				Index);
VOID RelocateConditional(PBYTE lpAddress,
	BYTE						InstSize,
	DWORD						CodeSize,
	PBYTE						Source,
	PBYTE						Destination,
	const BYTE					Type,
	const BYTE					Index,
	PBYTE						Offset);