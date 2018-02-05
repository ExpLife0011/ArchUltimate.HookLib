#include "stdafx.h"
#include "hook.h"

EXTERN DWORD WINAPI HookAssertLength(IN LPCVOID lpBaseAddress, CONST IN DWORD MinimumLength)
{
	_CodeInfo Info = { 0 };
	_DInst* Instructions = NULL;
	DWORD Size = 0;
	DWORD InstructionIndex = 0;
	unsigned int InstructionCount = 0;

	Info.code = (unsigned char*) lpBaseAddress;
	Info.codeLen = MAX_INSTRUCTIONS * 10;
	Info.codeOffset = 0;
	Info.features = DF_NONE;
	Info.dt = DISASM_TYPE;

	/* Assume that each instruction is 10 bytes at least */
	Instructions = (_DInst*) malloc(sizeof(_DecodedInst) * MAX_INSTRUCTIONS);
	if (!Instructions)
	{
		return 0;
	}

	/* Decode the instructions */
	if (distorm_decompose(&Info, Instructions, MAX_INSTRUCTIONS, &InstructionCount) == DECRES_INPUTERR
		|| InstructionCount == 0)
	{
		free(Instructions);
		return 0;
	}

	/* Loop through all the instructions. */
	for (InstructionIndex = 0; InstructionIndex < InstructionCount && Size < MinimumLength; InstructionIndex++)
	{
		Size += Instructions[InstructionIndex].size;
	}

	if (Size < MinimumLength)
	{
		free(Instructions);
		return 0;
	}

	free(Instructions);
	return Size;
}
