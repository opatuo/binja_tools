from capstone import *
from capstone.mips import *
from binaryninja import InstructionInfo, InstructionTextToken, InstructionTextTokenType

unconditional_branch_instructions = {"b", "j"}
function_return_instructions = {"jr"}
branch_instructions = {
    "beq",
    "beqz",
    "bgez",
    "bjezal",
    "bgtz",
    "blez",
    "bltz",
    "bltzal",
    "bne",
    "bnez",
}
call_destination_instructions = {"bal", "jal", "jalr"}


class MIPS16Disassembler:
    def __init__(self):
        self.disassembler32 = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_BIG_ENDIAN)
        self.disassembler32.detail = True

        self.disassembler16 = Cs(CS_ARCH_MIPS, CS_MODE_MICRO + CS_MODE_BIG_ENDIAN)
        self.disassembler16.detail = True

        self.disassembler = self.disassembler32

        self.micro_mode = False
        self.address_length = 4

    def decode(self, data, address):
        self._handle_mode_switch(address):
        raw_instruction = self._get_raw_instruction(data, address)
        if raw_instruction is None:
            return None
        return self._decode_impl(instruction, address)

    def text(self, data, address):
        self._handle_mode_switch(address):
        raw_instruction = self._get_raw_instruction(data, address)
        if raw_instruction is None:
            return None
        return self._text_impl(raw_instruction)

    def _handle_mode_switch(self, address):
        if address % 2 == 1:
            self._toggle_micro_mode_on()
        else
            self._toggle_micro_mode_off()

    def _address_length(self):
        return self.address_length

    def _toggle_micro_mode_on(self):
        self.disassembler = self.disassembler16
        self.micro_mode = True
        self.address_length = 2

    def _toggle_micro_mode_off(self):
        self.disassembler = self.disassembler32
        self.micro_mode = False
        self.address_length = 4

    def _get_raw_instruction(self, data, address):
        try:
            return next(self.disassembler.disasm(data, address, count=1))
        except CsError:
            return None
        except StopIteration:
            return None

    def _decode_impl(self, raw_instruction, address):
        result = InstructionInfo()
        result.length = self._address_length()

        destination = self._compute_branch_address(raw_instruction, address)

        if raw_instruction.mnemonic in unconditional_branch_instructions:
            result.add_branch(BranchType.UnconditionalBranch, destination)

        if raw_instruction.mnemonic in function_return_instructions:
            result.add_branch(BranchType.FunctionReturn)

        if raw_instruction.mnemonic in branch_instructions:
            result.add_branch(BranchType.TrueBranch, destination)
            # Take into account the delay slot when computing the false branch address
            result.add_branch(
                BranchType.FalseBranch, address + 2 * self._address_length()
            )

        if raw_instruction.mnemonic in call_destination_instructions:
            result.add_branch(BranchType.CallDestination, destination)

        return result

    def _compute_branch_address(self, raw_instruction, address):
        return address

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
