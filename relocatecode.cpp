#include "stdafx.h"
#include "hook.h"

EXTERN HStatus WINAPI HookRelocateCode(CONST IN PBYTE Code, IN DWORD Size, CONST IN PBYTE Source)
{
	_CodeInfo Info = { 0 };
	_DInst Instruction = { 0 };
	_DecodedInst InstructionEx = { 0 };
	_DInst* Instructions;
	DWORD InstructionIndex;
	unsigned int InstructionCount = 0;
	PBYTE InstructionAddress;
	BYTE InstructionDispIndex;
	BYTE InstructionOffsetIndex;
	LPSTR InstructionMnemonic;

	Info.code = (LPBYTE) Code;
	Info.codeLen = Size * 10;
	Info.features = DF_NONE;
	Info.dt = DISASM_TYPE;

	/* Check if the code the user requested is large enough to hold all the instructions we need. */
	Size = HookAssertLength(Code, Size);
	if (!Size)
	{
		return HOOK_INVALID_SIZE;
	}

	/* Assume that each instruction is 10 bytes at least */
	Instructions = (_DInst*) malloc(sizeof(_DecodedInst) * (Size * 10));
	if (!Instructions)
	{
		return HOOK_NOT_ENOUGH_SPACE;
	}

	/* Decode the instructions */
	if (distorm_decompose(&Info, Instructions, Size, &InstructionCount) == DECRES_INPUTERR
		|| Size == 0 || InstructionCount == 0)
	{
		free(Instructions);
		return HOOK_FAILED_API;
	}

	/* Loop through all the instructions. */
	for (InstructionIndex = 0; InstructionIndex < InstructionCount; InstructionIndex++)
	{
		Instruction = Instructions[InstructionIndex];

		/* Invalid instruction */
		if (Instruction.flags == FLAG_NOT_DECODABLE)
		{
			continue;
		}

		/* Parse the instruction for detailed information */
		distorm_format(&Info, &Instruction, &InstructionEx);

		InstructionMnemonic = (LPSTR) InstructionEx.mnemonic.p;

		/* The address of this instruction */
		InstructionAddress = Code + InstructionEx.offset;

		/* Start of the disp (example: [rip + 0xbeef] where the 0xbeef is our disp)
		-- dispSize is the size of our disp represented in bits, to get the index we take the size of our instruction, and take out the dispSize in bytes from it,
		-- leaving us with the start of the disp.
		*/
		InstructionDispIndex = InstructionEx.size - Instruction.dispSize / 8;

		/* We're going to check for 2 types of necessary relocations.
		-- Relatives rip addresses, and general 32bit relative addresses.
		*/
		for (int j = 0; j < OPERANDS_NO; j++)
		{
			_Operand op = Instruction.ops[j];
			if (op.size == 0)
			{
				/* Next instruction. */
				break;
			}

			/* The logic behind this is that the instruction always starts with the mnemonic, and ends with the offset. */
			InstructionOffsetIndex = Instruction.size - op.size / 8;

			/* O_SMEM: simple memory dereference with optional displacement (a single register memory dereference). */
			if (op.type == O_SMEM || op.type == O_MEM)
			{
				/* Examples: call qword ptr [rip + 0xbeef] */
				if (!(Instruction.flags & FLAG_RIP_RELATIVE))
					continue;

				RelocateExistingRelative(InstructionAddress,
					Source,
					Code,
					(SIZE_T) Instruction.disp,
					Instruction.dispSize,
					InstructionDispIndex);
			}
			/* O_PC: the relative address of a branch instruction (instruction.imm.addr). */
			else if (op.type == O_PC)
			{
				/* Is it a conditional jump? */
				if (IsConditionalJump((PBYTE) InstructionAddress, InstructionEx.size))
				{
					/* Does the relative jump go beyond our copied code? */
					if ((DWORD) Instruction.imm.addr > Size)
					{
						RelocateConditional(InstructionAddress,
							InstructionEx.size,
							Size,
							Source,
							Code,
							(BYTE) op.size,
							InstructionOffsetIndex,
							(PBYTE) Instruction.imm.addr);
					}
				}
				else if (!strcmp(InstructionMnemonic, "CALL") || !strcmp(InstructionMnemonic, "JMP"))
				{
					RelocateExistingRelative(InstructionAddress,
						Source,
						Code,
						(SIZE_T) Instruction.imm.addr,
						(BYTE) op.size,
						InstructionOffsetIndex);
				}
			}
		}
	}

	free(Instructions);
	return HOOK_NO_ERR;
}