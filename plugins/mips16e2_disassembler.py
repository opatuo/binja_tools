from capstone import *
from capstone.mips import *
from binaryninja import InstructionInfo

class MIPS16e2Disassembler:
    def __init__(self):
        self.disassembler = Cs(CS_ARCH_MIPS,  CS_MODE_MIPS32R6 + CS_MODE_BIG_ENDIAN)
        self.disassembler.detail = True
        self.disassembler.syntax = CS_OPT_SYNTAX_INTEL
        self.micro_mode = False

    def toggle_micro_mode_on(self):
        self.disassembler.mode = CS_MODE_MICRO + CS_MODE_MIPS32R6 + CS_MODE_BIG_ENDIAN
        self.micro_mode = True

    def toggle_micro_mode_off(self):
        self.disassembler.mode = CS_MODE_MIPS32R6 + CS_MODE_BIG_ENDIAN
        self.micro_mode = False

    def micro_mode_enabled(self):
        return self.micro_mode

    def decode(self, data, address):
        raw_instruction = _get_raw_instruction(self, data, address)
        if raw_instruction is None:
            return None
        return _decode_impl(self, instruction)

    def text(self, data, address):
        raw_instruction = _get_raw_instruction(self, data, address)

    def _get_raw_instruction(self, data, address):
        try:
            return next(self.disassembler.disasm(data, address, count=1))
        except CsError:
            return None
        except StopIteration:
            return None

    def _decode_impl(self, raw_instruction):
        result = InstructionInfo()
        if self.micro_mode:
            result.length = 2
        else:
            result.length = 4
        return result
