#pragma once
#include "stdafx.h"

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

typedef HStatus(WINAPI* tHookDetour) (CONST IN PDetourContext Context);
// tHookDetour HookDetour;

typedef HStatus(WINAPI* tHookDetourContextRestore)(CONST IN PDetourContext Context);
// tHookDetourContextRestore HookDetourContextRestore;

typedef HStatus(WINAPI* tHookRelocateCode)(CONST IN PBYTE Code, IN DWORD Size, CONST IN PBYTE Source);
// tHookRelocateCode HookRelocateCode;

typedef PVOID(WINAPI* tHookCreateCave32)(IN LPVOID lpBaseAddress, CONST IN SIZE_T Size);
// tHookCreateCave32 HookCreateCave32;

typedef PVOID(WINAPI* tHookCreateCave64)(IN LPVOID lpBaseAddress, CONST IN SIZE_T Size);
// tHookCreateCave64 HookCreateCave64;

typedef DWORD(WINAPI* tHookAssertLength)(IN LPCVOID lpBaseAddress, CONST IN DWORD MinimumLength);
// tHookAssertLength HookAssertLength;

typedef PVOID(WINAPI* tHookRecreateCode)(CONST IN PBYTE lpBaseAddress, CONST IN DWORD dwMinimumSize);
// tHookRecreateCode HookRecreateCode;