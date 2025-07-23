from binaryninja.architecture import Architecture
from binaryninja.function import RegisterInfo
from binaryninja import Endianness

from .instruction import MIPS16e2Disassembler

class MIPS16e2Architecture(Architecture):
	name = 'mips16e2'
    # These values are taken from binaryninja-api/arch/mips/arch_mips.cpp
    max_instr_length = 4
    address_size = 4		# 32-bit addresses, the process will read 2 16-bit address at once in 16 bit mode
    default_int_size = 4
    instr_alignment = 4

    disassembler = MIPS16e2Disassembler()

    endianness = Endianness.BigEndian

    # we are using the ABI names here because those are the register names returned by capstone.
    # https://refspecs.linuxfoundation.org/elf/mipsabi.pdf
    regs = {
              'zero': RegisterInfo('zero', address_size),
              'at': RegisterInfo('at', address_size),
              'v0': RegisterInfo('v0', address_size),
              'v1': RegisterInfo('v1', address_size),
              'a0': RegisterInfo('a0', address_size),
              'a1': RegisterInfo('a1', address_size),
              'a2': RegisterInfo('a2', address_size),
              'a3': RegisterInfo('a3', address_size),
              't0': RegisterInfo('t0', address_size),
              't1': RegisterInfo('t1', address_size),
              't2': RegisterInfo('t2', address_size),
              't3': RegisterInfo('t3', address_size),
              't4': RegisterInfo('t4', address_size),
              't5': RegisterInfo('t5', address_size),
              't6': RegisterInfo('t6', address_size),
              't7': RegisterInfo('t7', address_size),
              's0': RegisterInfo('s0', address_size),
              's1': RegisterInfo('s1', address_size),
              's2': RegisterInfo('s2', address_size),
              's3': RegisterInfo('s3', address_size),
              's4': RegisterInfo('s4', address_size),
              's5': RegisterInfo('s5', address_size),
              's6': RegisterInfo('s6', address_size),
              's7': RegisterInfo('s7', address_size),
              't8': RegisterInfo('t8', address_size),
              't9': RegisterInfo('t9', address_size),
              'kt0': RegisterInfo('kt0', address_size),
              'kt1': RegisterInfo('kt1', address_size),
              'gp': RegisterInfo('gp', address_size),
              'sp': RegisterInfo('sp', address_size),
              'fp': RegisterInfo('fp', address_size), # also s8
              'ra': RegisterInfo('ra', address_size),
           }

    stack_pointer = "sp"

    def get_instruction_info(self, data, address):
        return disassembler.decode(data, address)

    def get_instruction_text(self, data, address):
        return disassembler.text(data, address)

MIPS16e2Architecture.register()
