from capstone import *
from capstone.mips import *
from binaryninja import InstructionInfo

class MIPS16Disassembler:
    def __init__(self):
        self.disassembler = Cs(CS_ARCH_MIPS,  CS_MODE_MIPS32 + CS_MODE_BIG_ENDIAN)
        self.disassembler.detail = True

        self.micro_mode = False
        self.address_length = 4

    def decode(self, data, address):
        raw_instruction = _get_raw_instruction(self, data, address)
        if raw_instruction is None:
            return None
        return _decode_impl(self, instruction)

    def text(self, data, address):
        raw_instruction = _get_raw_instruction(self, data, address)
        if raw_instruction is None:
            return None

    def address_length(self):
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
        result.length = address_length(self)
        return result
