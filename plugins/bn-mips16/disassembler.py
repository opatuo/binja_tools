from capstone import *
from capstone.mips import *
from binaryninja import InstructionInfo, InstructionTextToken, InstructionTextTokenType


class MIPS16Disassembler:
    def __init__(self):
        self.disassembler = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_BIG_ENDIAN)
        self.disassembler.detail = True

        self.micro_mode = False
        self.address_length = 4

    def decode(self, data, address):
        raw_instruction = self._get_raw_instruction(data, address)
        if raw_instruction is None:
            return None
        return self._decode_impl(instruction)

    def text(self, data, address):
        raw_instruction = self._get_raw_instruction(data, address)
        if raw_instruction is None:
            return None
        return self._text_impl(raw_instruction)

    def _address_length(self):
        return self.address_length

    def _toggle_micro_mode_on(self):
        self.disassembler.mode = CS_MODE_MICRO + CS_MODE_MIPS32 + CS_MODE_BIG_ENDIAN
        self.micro_mode = True
        self.address_length = 2

    def _toggle_micro_mode_off(self):
        self.disassembler.mode = CS_MODE_MIPS32 + CS_MODE_BIG_ENDIAN
        self.micro_mode = False
        self.address_length = 4

    def _get_raw_instruction(self, data, address):
        try:
            return next(self.disassembler.disasm(data, address, count=1))
        except CsError:
            return None
        except StopIteration:
            return None

    def _decode_impl(self, raw_instruction):
        result = InstructionInfo()
        result.length = self._address_length()
        return result

    def _text_impl(self, raw_instruction):
        tokens = []
        tokens.append(
            InstructionTextToken(
                InstructionTextTokenType.InstructionToken, raw_instruction.mnemonic
            )
        )
        for i in raw_instruction.operands:
            if i.type == MIPS_OP_REG:
                tokens.append(
                    InstructionTextToken(
                        InstructionTextTokenType.RegisterToken,
                        raw_instruction.reg_name(i.value.reg),
                    )
                )
            if i.type == MIPS_OP_IMM:
                tokens.append(
                    InstructionTextToken(
                        InstructionTextTokenType.IntegerToken,
                        hex(i.value.imm),
                        value=i.value.imm,
                    )
                )
            if i.type == MIPS_OP_MEM:
                tokens.append(
                    InstructionTextToken(
                        InstructionTextTokenType.BeginMemoryOperandToken, "("
                    )
                )
                tokens.append(
                    InstructionTextToken(
                        InstructionTextTokenType.RegisterToken,
                        raw_instruction.reg_name(i.value.mem.base),
                    )
                )
                tokens.append(
                    InstructionTextToken(
                        InstructionTextTokenType.IntegerToken,
                        hex(i.value.mem.disp),
                        value=i.value.mem.disp,
                    )
                )
                tokens.append(
                    InstructionTextToken(
                        InstructionTextTokenType.EndMemoryOperandToken, ")"
                    )
                )

        return tokens, self._address_length()
