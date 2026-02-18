#define _CRT_SECURE_NO_WARNINGS
#define NOMINMAX

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "binaryninjaapi.h"
#include "lowlevelilinstruction.h"
#include "mips.h"
#include "il.h"

using namespace BinaryNinja;
using namespace mips;
using namespace std;


class UniversalArchitecture: BinaryNinja::Architecture
{
public:

	UniversalArchitecture(const std::string& name) : Architecture(name)
	{
		//Ref<Settings> settings = Settings::Instance();
		//uint32_t flag_pseudo_ops = settings->Get<bool>("arch.mips.disassembly.pseudoOps") ? DECOMPOSE_FLAGS_PSEUDO_OP : 0;
	}

	virtual bool Disassemble(const uint8_t* data, uint64_t addr, size_t maxLen, Instruction& result)
	{
		return true;
	}

	virtual size_t GetAddressSize() const override
	{
		return 0U;
	}

	virtual BNEndianness GetEndianness() const override
	{
        return BigEndian;
	}


	virtual size_t GetInstructionAlignment() const override
	{
		return 4;
	}

	virtual size_t GetMaxInstructionLength() const override
	{
		return 8; // To disassemble delay slots, allow two instructions
	}

	virtual size_t GetOpcodeDisplayLength() const override
	{
		return 4;
	}

	virtual bool CanAssemble() const override
	{
		return true;
	}

	bool Assemble(const string& code, uint64_t addr, DataBuffer& result, string& errors) override
	{
        (void)code;
		(void)addr;
        (void)result;
        (void)errors;

        return true;
	}

	virtual bool GetInstructionLowLevelIL(const uint8_t* data, uint64_t addr, size_t& len, LowLevelILFunction& il) override
	{
        (void)data;
        (void)addr;
        (void)len;
        (void)il;


        return true;
	}

	virtual bool GetInstructionInfo(const uint8_t* data, uint64_t addr, size_t maxLen, InstructionInfo& result) override
	{
        (void)data;
        (void)addr;
        (void)maxLen;
        (void)result;

		return true;
	}

	virtual bool GetInstructionText(const uint8_t* data, uint64_t addr, size_t& len, vector<InstructionTextToken>& result) override
	{
        (void)data;
        (void)addr;
        (void)len;
        (void)result;

		return true;
	}

	virtual string GetIntrinsicName(const uint32_t intrinsic) override
	{
        (void)intrinsic;
        return "";
	}

	virtual vector<uint32_t> GetAllIntrinsics() override
	{
		return std::vector<uint32_t>();
	}

	virtual std::vector<NameAndType> GetIntrinsicInputs(const uint32_t intrinsic) override
	{
		return std::vector<NameAndType>();
	}

	virtual vector<Confidence<Ref<Type>>> GetIntrinsicOutputs(const uint32_t intrinsic) override
	{
        return std::vector<Confidence<Ref<Type>>>();
	}

	virtual bool IsNeverBranchPatchAvailable(const uint8_t* data, uint64_t addr, size_t len) override
	{
        (void)data;
        (void)addr;
        (void)len;
		return false;
	}

	virtual bool IsAlwaysBranchPatchAvailable(const uint8_t* data, uint64_t addr, size_t len) override
	{
        (void)data;
        (void)addr;
        (void)len;
		return false;
	}

	virtual bool IsInvertBranchPatchAvailable(const uint8_t* data, uint64_t addr, size_t len) override
	{
        (void)data;
        (void)addr;
        (void)len;
		return false;
	}

	virtual bool IsSkipAndReturnZeroPatchAvailable(const uint8_t* data, uint64_t addr, size_t len) override
	{
        (void)data;
        (void)addr;
        (void)len;
		return false;
	}

	virtual bool IsSkipAndReturnValuePatchAvailable(const uint8_t* data, uint64_t addr, size_t len) override
	{
        (void)data;
        (void)addr;
        (void)len;
		return false;
	}

	virtual bool ConvertToNop(uint8_t* data, uint64_t, size_t len) override
	{
        (void)data;
        (void)addr;
        (void)len;
		return false;
	}

	virtual bool AlwaysBranch(uint8_t* data, uint64_t addr, size_t len) override
	{
        (void)data;
        (void)addr;
        (void)len;
		return false;
	}

	virtual bool InvertBranch(uint8_t* data, uint64_t addr, size_t len) override
	{
        (void)data;
        (void)addr;
        (void)len;
		return false;
	}

	virtual bool SkipAndReturnValue(uint8_t* data, uint64_t addr, size_t len, uint64_t value) override
	{
        (void)data;
        (void)addr;
        (void)len;
		return false;
	}

	virtual string GetRegisterName(uint32_t reg) override
	{
        (void)reg;
        return "";
	}

	virtual string GetFlagName(uint32_t reg) override
	{
        (void)reg;
        return "";
	}

	virtual vector<uint32_t> GetFullWidthRegisters() override
	{
        return std::vector<uint32_t>();
	}

	virtual vector<uint32_t> GetAllRegisters() override
	{
        return std::vector<uint32_t>();
	}

	virtual vector<uint32_t> GetAllFlags() override
	{
        return std::vector<uint32_t>();
	}

	virtual BNRegisterInfo GetRegisterInfo(const uint32_t reg) override
	{
		BNRegisterInfo result = {reg, 0, 0, NoExtend};
		return result;
	}

	virtual uint32_t GetStackPointerRegister() const override
	{
		return 0;
	}

	virtual uint32_t GetLinkRegister() const override
	{
		return 0;
	}

	virtual vector<uint32_t> GetSystemRegisters() override
	{
        return std::vector<uint32_t>();
	}
};

class UniversalCallingConvention: public CallingConvention
{
public:
	UniversalCallingConvention(Architecture* arch): CallingConvention(arch, "o32")
	{
	}

	virtual uint32_t GetIntegerReturnValueRegister() override
	{
		return REG_V0;
	}

	virtual uint32_t GetHighIntegerReturnValueRegister() override
	{
		return REG_V1;
	}

	virtual vector<uint32_t> GetIntegerArgumentRegisters() override
	{
		return vector<uint32_t>{ REG_A0, REG_A1, REG_A2, REG_A3 };
	}

	virtual bool IsStackReservedForArgumentRegisters() override
	{
		return true;
	}

	virtual vector<uint32_t> GetCallerSavedRegisters() override
	{
		return vector<uint32_t> { REG_AT, REG_V0, REG_V1, REG_A0, REG_A1, REG_A2, REG_A3, REG_T0, REG_T1,
			REG_T2, REG_T3, REG_T4, REG_T5, REG_T6, REG_T7, REG_T8, REG_T9 };
	}

	virtual vector<uint32_t> GetCalleeSavedRegisters() override
	{
		return vector<uint32_t> { REG_S0, REG_S1, REG_S2, REG_S3, REG_S4, REG_S5, REG_S6, REG_S7,
			REG_GP, REG_FP };
	}

	virtual uint32_t GetGlobalPointerRegister() override
	{
		return REG_GP;
	}

	virtual vector<uint32_t> GetImplicitlyDefinedRegisters() override
	{
		return vector<uint32_t> { REG_T9 };
	}

	virtual RegisterValue GetIncomingRegisterValue(uint32_t reg, Function* func) override
	{
		RegisterValue result;
		if (reg == REG_T9)
		{
			result.state = ConstantPointerValue;
			result.value = func->GetStart();
		}
		return result;
	}
};

class MipsPS2CallingConvention: public CallingConvention
{
public:
	MipsPS2CallingConvention(Architecture* arch): CallingConvention(arch, "ps2")
	{
	}
	virtual uint32_t GetIntegerReturnValueRegister() override
	{
		return REG_V0;
	}

	virtual uint32_t GetHighIntegerReturnValueRegister() override
	{
		return REG_V1;
	}

	virtual vector<uint32_t> GetIntegerArgumentRegisters() override
	{
		return vector<uint32_t>{ REG_A0, REG_A1, REG_A2, REG_A3, REG_T0, REG_T1, REG_T2, REG_T3 };
	}

	virtual vector<uint32_t> GetFloatArgumentRegisters() override
	{
		return vector<uint32_t>{ FPREG_F12, FPREG_F13, FPREG_F14, FPREG_F15, FPREG_F16, FPREG_F17, FPREG_F18, FPREG_F19 };
	}

	virtual uint32_t GetFloatReturnValueRegister() override
	{
		return FPREG_F0;
	}

	virtual bool IsStackReservedForArgumentRegisters() override
	{
		return true;
	}

	virtual vector<uint32_t> GetCallerSavedRegisters() override
	{
		return vector<uint32_t> { REG_AT, REG_V0, REG_V1, REG_A0, REG_A1, REG_A2, REG_A3, REG_T0, REG_T1,
			REG_T2, REG_T3, REG_T4, REG_T5, REG_T6, REG_T7, REG_T8, REG_T9 };
	}

	virtual vector<uint32_t> GetCalleeSavedRegisters() override
	{
		return vector<uint32_t> { REG_S0, REG_S1, REG_S2, REG_S3, REG_S4, REG_S5, REG_S6, REG_S7,
			REG_GP, REG_FP, FPREG_F20, FPREG_F21, FPREG_F22, FPREG_F23, FPREG_F24, FPREG_F25,
			FPREG_F26, FPREG_F27, FPREG_F28, FPREG_F29, FPREG_F30, FPREG_F31 };
	}

	virtual uint32_t GetGlobalPointerRegister() override
	{
		return REG_GP;
	}

	virtual vector<uint32_t> GetImplicitlyDefinedRegisters() override
	{
		return vector<uint32_t> { REG_T9 };
	}

	virtual RegisterValue GetIncomingRegisterValue(uint32_t reg, Function* func) override
	{
		RegisterValue result;
		if (reg == REG_T9)
		{
			result.state = ConstantPointerValue;
			result.value = func->GetStart();
		}
		return result;
	}
};

class MipsN64CallingConvention: public CallingConvention
{
public:
	MipsN64CallingConvention(Architecture* arch): CallingConvention(arch, "n64")
	{
	}

	virtual uint32_t GetIntegerReturnValueRegister() override
	{
		return REG_V0;
	}

	virtual uint32_t GetHighIntegerReturnValueRegister() override
	{
		return REG_V1;
	}

	virtual vector<uint32_t> GetIntegerArgumentRegisters() override
	{
		return vector<uint32_t>{
			REG_A0, REG_A1, REG_A2, REG_A3,
			REG_A4, REG_A5, REG_A6, REG_A7,
		};
	}

	virtual bool IsStackReservedForArgumentRegisters() override
	{
		return false;
	}

	virtual vector<uint32_t> GetCallerSavedRegisters() override
	{
		return vector<uint32_t> { REG_AT, REG_V0, REG_V1, REG_A0, REG_A1, REG_A2, REG_A3, REG_A4, REG_A5,
			REG_A6, REG_A7, REG_T4, REG_T5, REG_T6, REG_T7, REG_T8, REG_T9, REG_RA,
			FPREG_F0, FPREG_F1, FPREG_F2, FPREG_F3, FPREG_F4, FPREG_F5, FPREG_F6, FPREG_F7, FPREG_F8,
			FPREG_F9, FPREG_F10, FPREG_F11, FPREG_F12, FPREG_F13, FPREG_F14, FPREG_F15, FPREG_F16, FPREG_F17,
			FPREG_F18, FPREG_F19, FPREG_F20, FPREG_F21, FPREG_F22, FPREG_F23, };
	}

	virtual vector<uint32_t> GetCalleeSavedRegisters() override
	{
		return vector<uint32_t> { REG_S0, REG_S1, REG_S2, REG_S3, REG_S4, REG_S5, REG_S6, REG_S7,
			REG_GP, REG_FP, FPREG_F24, FPREG_F25, FPREG_F26, FPREG_F27, FPREG_F28, FPREG_F29, FPREG_F30, FPREG_F31 };
	}

	virtual uint32_t GetGlobalPointerRegister() override
	{
		return REG_GP;
	}

	virtual vector<uint32_t> GetImplicitlyDefinedRegisters() override
	{
		return vector<uint32_t> { REG_T9 };
	}

	virtual RegisterValue GetIncomingRegisterValue(uint32_t reg, Function* func) override
	{
		RegisterValue result;
		if (reg == REG_T9)
		{
			result.state = ConstantPointerValue;
			result.value = func->GetStart();
		}
		return result;
	}
};

class MipsLinuxSyscallCallingConvention: public CallingConvention
{
public:
	MipsLinuxSyscallCallingConvention(Architecture* arch): CallingConvention(arch, "linux-syscall")
	{
	}

	virtual uint32_t GetIntegerReturnValueRegister() override
	{
		return REG_V0;
	}

	virtual uint32_t GetHighIntegerReturnValueRegister() override
	{
		return REG_V1;
	}

	virtual vector<uint32_t> GetIntegerArgumentRegisters() override
	{
		return vector<uint32_t>{ REG_V0, REG_A0, REG_A1, REG_A2, REG_A3 };
	}

	virtual vector<uint32_t> GetCallerSavedRegisters() override
	{
		return vector<uint32_t> { REG_AT, REG_V0, REG_V1 };
	}

	virtual vector<uint32_t> GetCalleeSavedRegisters() override
	{
		return vector<uint32_t> { REG_S0, REG_S1, REG_S2, REG_S3, REG_S4, REG_S5, REG_S6, REG_S7,
			REG_GP, REG_FP };
	}

	virtual bool IsEligibleForHeuristics() override
	{
		return false;
	}

	virtual bool IsStackReservedForArgumentRegisters() override
	{
		return true;
	}
};

class MipsLinuxRtlResolveCallingConvention: public CallingConvention
{
public:
	MipsLinuxRtlResolveCallingConvention(Architecture* arch): CallingConvention(arch, "linux-rtlresolve")
	{
	}

	virtual vector<uint32_t> GetIntegerArgumentRegisters() override
	{
		return vector<uint32_t>{
			REG_T7, /* return address of caller of PLT stub */
			REG_T8 /* symbol index */
		};
	}

	virtual uint32_t GetIntegerReturnValueRegister() override
	{
		return REG_T0;
	}

	virtual bool IsEligibleForHeuristics() override
	{
		return false;
	}
};

class MipsImportedFunctionRecognizer: public FunctionRecognizer
{
private:
	bool RecognizeELFPLTEntries0(BinaryView* data, Function* func, LowLevelILFunction* il)
	{
		// Look for the following code pattern:
		// $t7 = got_hi
		// $t9 = [$t7 + got_lo].d
		// $t8 = $t7 + got_lo
		// OPTIONAL: $t7 = got_hi
		// tailcall($t9)
		if (il->GetInstructionCount() < 4)
			return false;
		if (il->GetInstructionCount() > 5)
			return false;

		LowLevelILInstruction lui = il->GetInstruction(0);
		if (lui.operation != LLIL_SET_REG)
			return false;
		LowLevelILInstruction luiOperand = lui.GetSourceExpr<LLIL_SET_REG>();
		if (!LowLevelILFunction::IsConstantType(luiOperand.operation))
			return false;
		if (luiOperand.size != func->GetArchitecture()->GetAddressSize())
			return false;
		uint64_t pltHi = luiOperand.GetConstant();
		uint32_t pltReg = lui.GetDestRegister<LLIL_SET_REG>();

		LowLevelILInstruction ld = il->GetInstruction(1);
		if (ld.operation != LLIL_SET_REG)
			return false;
		uint32_t targetReg = ld.GetDestRegister<LLIL_SET_REG>();
		LowLevelILInstruction ldOperand = ld.GetSourceExpr<LLIL_SET_REG>();
		if (ldOperand.operation != LLIL_LOAD)
			return false;
		if (ldOperand.size != func->GetArchitecture()->GetAddressSize())
			return false;
		LowLevelILInstruction ldAddrOperand = ldOperand.GetSourceExpr<LLIL_LOAD>();
		uint64_t entry = pltHi;
		int64_t ldAddrRightOperandValue = 0;

		if ((ldAddrOperand.operation == LLIL_ADD) || (ldAddrOperand.operation == LLIL_SUB))
		{
			LowLevelILInstruction ldAddrLeftOperand = ldAddrOperand.GetRawOperandAsExpr(0);
			LowLevelILInstruction ldAddrRightOperand = ldAddrOperand.GetRawOperandAsExpr(1);
			if (ldAddrLeftOperand.operation != LLIL_REG)
				return false;
			if (ldAddrLeftOperand.GetSourceRegister<LLIL_REG>() != pltReg)
				return false;
			if (!LowLevelILFunction::IsConstantType(ldAddrRightOperand.operation))
				return false;
			ldAddrRightOperandValue = ldAddrRightOperand.GetConstant();
			if (ldAddrOperand.operation == LLIL_SUB)
				ldAddrRightOperandValue = -ldAddrRightOperandValue;
			entry = pltHi + ldAddrRightOperandValue;
		}
		else if (ldAddrOperand.operation != LLIL_REG) //If theres no constant
			return false;

		Ref<Symbol> sym = data->GetSymbolByAddress(entry);
		if (!sym)
			return false;
		if (sym->GetType() != ImportAddressSymbol)
			return false;

		LowLevelILInstruction add = il->GetInstruction(2);
		if (add.operation != LLIL_SET_REG)
			return false;
		LowLevelILInstruction addOperand = add.GetSourceExpr<LLIL_SET_REG>();

		if (addOperand.operation == LLIL_ADD)
		{
			LowLevelILInstruction addLeftOperand = addOperand.GetLeftExpr<LLIL_ADD>();
			LowLevelILInstruction addRightOperand = addOperand.GetRightExpr<LLIL_ADD>();
			if (addLeftOperand.operation != LLIL_REG)
				return false;
			if (addLeftOperand.GetSourceRegister<LLIL_REG>() != pltReg)
				return false;
			if (!LowLevelILFunction::IsConstantType(addRightOperand.operation))
				return false;
			if (addRightOperand.GetConstant() != (ldAddrRightOperandValue & 0xffffffff))
				return false;
		}
		else if ((addOperand.operation != LLIL_REG) || (addOperand.GetSourceRegister<LLIL_REG>() != pltReg)) //Simple assignment
			return false;

		LowLevelILInstruction jump = il->GetInstruction(3);
		if (jump.operation == LLIL_SET_REG)
		{
			if (il->GetInstructionCount() != 5)
				return false;
			if (jump.GetDestRegister<LLIL_SET_REG>() != pltReg)
				return false;
			LowLevelILInstruction luiOperand = jump.GetSourceExpr<LLIL_SET_REG>();
			if (!LowLevelILFunction::IsConstantType(luiOperand.operation))
				return false;
			if (luiOperand.size != func->GetArchitecture()->GetAddressSize())
				return false;
			if (((uint64_t) luiOperand.GetConstant()) != pltHi)
				return false;
			jump = il->GetInstruction(4);
		}

		if ((jump.operation != LLIL_JUMP) && (jump.operation != LLIL_TAILCALL))
			return false;
		LowLevelILInstruction jumpOperand = (jump.operation == LLIL_JUMP) ? jump.GetDestExpr<LLIL_JUMP>() : jump.GetDestExpr<LLIL_TAILCALL>();
		if (jumpOperand.operation != LLIL_REG)
			return false;
		if (jumpOperand.GetSourceRegister<LLIL_REG>() != targetReg)
			return false;

		Ref<Symbol> funcSym = Symbol::ImportedFunctionFromImportAddressSymbol(sym, func->GetStart());
		data->DefineAutoSymbol(funcSym);

		auto extSym = data->GetSymbolsByName(funcSym->GetRawName(), data->GetExternalNameSpace());
		if (!extSym.empty()) {
			DataVariable var;
			if (data->GetDataVariableAtAddress(extSym.front()->GetAddress(), var))
			{
				func->ApplyImportedTypes(funcSym, var.type.GetValue());
			}
			return true;
		}
		return false;
	}


	bool RecognizeELFPLTEntries1(BinaryView* data, Function* func, LowLevelILFunction* il)
	{
		LowLevelILInstruction tmp, left, right;

		// Look for the following code pattern:
		// 0: $t9 = [$gp - ????]	// get to base of GOT
		// 1: $t7 = $ra				// transmit address so RTLD!service_stub() can return to caller
		// 2: $t8 = ??				// transmit symbol index to RTLD!service_stub()
		// 3: call($t9)				// call RTLD!service_stub()
		// 4: tailcall(??)
		if (il->GetInstructionCount() != 5)
			return false;

		// test instruction0
		tmp = il->GetInstruction(0); // $t9 = ...
		if (tmp.operation != LLIL_SET_REG) return false;
		tmp = tmp.GetSourceExpr<LLIL_SET_REG>(); // [$gp - ????]
		if (tmp.operation != LLIL_LOAD) return false;
		tmp = tmp.GetSourceExpr<LLIL_LOAD>(); // $gp - ????
		if (tmp.operation != LLIL_SUB) return false;
		auto value = il->GetExprValue(tmp); // accept if Binja has resolved to a value
		//if (value.state != ConstantValue) return false;
		//uint64_t got_base = value.value;
		//break;

		// test instruction1
		tmp = il->GetInstruction(1); // $t7 = $ra
		if (tmp.operation != LLIL_SET_REG) return false;
		if (tmp.GetDestRegister<LLIL_SET_REG>() != REG_T7) return false; // $t7
		tmp = tmp.GetSourceExpr<LLIL_SET_REG>(); // $ra
		if (tmp.operation != LLIL_REG) return false;
		if (tmp.GetSourceRegister<LLIL_REG>() != REG_RA) return false;

		// test instruction2
		tmp = il->GetInstruction(2); // $t8 = ????
		if (tmp.operation != LLIL_SET_REG) return false;
		tmp = tmp.GetSourceExpr<LLIL_SET_REG>(); // ????
		value = il->GetExprValue(tmp); // accept if Binja has resolved to a value
		if (value.state != ConstantValue) return false;

		// test instruction3
		tmp = il->GetInstruction(3); // call($t9)
		if (tmp.operation != LLIL_CALL) return false;
		tmp = tmp.GetDestExpr<LLIL_CALL>(); // ????
		if (tmp.GetSourceRegister<LLIL_REG>() != REG_T9) return false;

		// test instruction4
		tmp = il->GetInstruction(4); // tailcall(??)
		if (tmp.operation != LLIL_TAILCALL) return false;

		// There should be three symbols:
		// 1. ImportedFunctionSymbol has address of the PLT stub (where we are now)
		// 2. ImportAddressSymbol has address of corresponding GOT entry
		// 3. ExternalSymbol has address of corresponding address in .extern
		//
		// We need to locate #3, resolve its type, and apply it to #1
		Ref<Symbol> pltSym = data->GetSymbolByAddress(func->GetStart());

		if (pltSym)
		{
			auto extSym = data->GetSymbolsByName(pltSym->GetRawName(), data->GetExternalNameSpace());
			if (!extSym.empty()) {
				DataVariable var;
				if (data->GetDataVariableAtAddress(extSym.front()->GetAddress(), var))
				{
					func->ApplyImportedTypes(pltSym, var.type.GetValue());
				}
				return true;
			}
		}

		return false;
	}


	bool RecognizeELFPLTEntries2(BinaryView* data, Function* func, LowLevelILFunction* il)
	{
		// Look for the following code pattern:
		// $t7 = addr_past_got_end
		// $t9 = [$t7 - backward_offset_into_got].d
		// $t8 = $t7 + (-backward_offset_into_got)
		// OPTIONAL: $t7 = addr_past_got_end
		// tailcall($t9)
		if (il->GetInstructionCount() < 4)
			return false;
		if (il->GetInstructionCount() > 5)
			return false;

		LowLevelILInstruction lui = il->GetInstruction(0);
		if (lui.operation != LLIL_SET_REG)
			return false;
		LowLevelILInstruction luiOperand = lui.GetSourceExpr<LLIL_SET_REG>();
		if (!LowLevelILFunction::IsConstantType(luiOperand.operation))
			return false;
		if (luiOperand.size != func->GetArchitecture()->GetAddressSize())
			return false;
		uint64_t addrPastGot = luiOperand.GetConstant();
		uint32_t pltReg = lui.GetDestRegister<LLIL_SET_REG>();

		LowLevelILInstruction ld = il->GetInstruction(1);
		if (ld.operation != LLIL_SET_REG)
			return false;
		uint32_t targetReg = ld.GetDestRegister<LLIL_SET_REG>();
		LowLevelILInstruction ldOperand = ld.GetSourceExpr<LLIL_SET_REG>();
		if (ldOperand.operation != LLIL_LOAD)
			return false;
		if (ldOperand.size != func->GetArchitecture()->GetAddressSize())
			return false;
		LowLevelILInstruction ldAddrOperand = ldOperand.GetSourceExpr<LLIL_LOAD>();
		uint64_t entry = addrPastGot;
		int64_t ldAddrRightOperandValue = 0;

		if ((ldAddrOperand.operation == LLIL_ADD) || (ldAddrOperand.operation == LLIL_SUB))
		{
			LowLevelILInstruction ldAddrLeftOperand = ldAddrOperand.GetRawOperandAsExpr(0);
			LowLevelILInstruction ldAddrRightOperand = ldAddrOperand.GetRawOperandAsExpr(1);
			if (ldAddrLeftOperand.operation != LLIL_REG)
				return false;
			if (ldAddrLeftOperand.GetSourceRegister<LLIL_REG>() != pltReg)
				return false;
			if (!LowLevelILFunction::IsConstantType(ldAddrRightOperand.operation))
				return false;
			ldAddrRightOperandValue = ldAddrRightOperand.GetConstant();
			if (ldAddrOperand.operation == LLIL_SUB)
				ldAddrRightOperandValue = -ldAddrRightOperandValue;
			entry = addrPastGot + ldAddrRightOperandValue;
		}
		else if (ldAddrOperand.operation != LLIL_REG) //If theres no constant
			return false;

		Ref<Symbol> sym = data->GetSymbolByAddress(entry);
		if (!sym)
			return false;
		if (sym->GetType() != ImportAddressSymbol)
			return false;

		LowLevelILInstruction add = il->GetInstruction(2);
		if (add.operation != LLIL_SET_REG)
			return false;
		LowLevelILInstruction addOperand = add.GetSourceExpr<LLIL_SET_REG>();

		if (addOperand.operation == LLIL_ADD)
		{
			LowLevelILInstruction addLeftOperand = addOperand.GetLeftExpr<LLIL_ADD>();
			LowLevelILInstruction addRightOperand = addOperand.GetRightExpr<LLIL_ADD>();
			if (addLeftOperand.operation != LLIL_REG)
				return false;
			if (addLeftOperand.GetSourceRegister<LLIL_REG>() != pltReg)
				return false;
			if (!LowLevelILFunction::IsConstantType(addRightOperand.operation))
				return false;
			if (addRightOperand.GetConstant() != ldAddrRightOperandValue)
				return false;
		}
		else if ((addOperand.operation != LLIL_REG) || (addOperand.GetSourceRegister<LLIL_REG>() != pltReg)) //Simple assignment
			return false;

		LowLevelILInstruction jump = il->GetInstruction(3);
		if (jump.operation == LLIL_SET_REG)
		{
			if (il->GetInstructionCount() != 5)
				return false;
			if (jump.GetDestRegister<LLIL_SET_REG>() != pltReg)
				return false;
			LowLevelILInstruction luiOperand = jump.GetSourceExpr<LLIL_SET_REG>();
			if (!LowLevelILFunction::IsConstantType(luiOperand.operation))
				return false;
			if (luiOperand.size != func->GetArchitecture()->GetAddressSize())
				return false;
			if (((uint64_t) luiOperand.GetConstant()) != addrPastGot)
				return false;
			jump = il->GetInstruction(4);
		}

		if ((jump.operation != LLIL_JUMP) && (jump.operation != LLIL_TAILCALL))
			return false;
		LowLevelILInstruction jumpOperand = (jump.operation == LLIL_JUMP) ? jump.GetDestExpr<LLIL_JUMP>() : jump.GetDestExpr<LLIL_TAILCALL>();
		if (jumpOperand.operation != LLIL_REG)
			return false;
		if (jumpOperand.GetSourceRegister<LLIL_REG>() != targetReg)
			return false;

		Ref<Symbol> funcSym = Symbol::ImportedFunctionFromImportAddressSymbol(sym, func->GetStart());
		data->DefineAutoSymbol(funcSym);

		auto extSym = data->GetSymbolsByName(funcSym->GetRawName(), data->GetExternalNameSpace());
		if (!extSym.empty()) {
			DataVariable var;
			if (data->GetDataVariableAtAddress(extSym.front()->GetAddress(), var))
			{
				func->ApplyImportedTypes(funcSym, var.type.GetValue());
			}
			return true;
		}
		return false;
	}


public:
	virtual bool RecognizeLowLevelIL(BinaryView* data, Function* func, LowLevelILFunction* il) override
	{
		if (RecognizeELFPLTEntries0(data, func, il))
			return true;

		if (RecognizeELFPLTEntries1(data, func, il))
			return true;

		if (RecognizeELFPLTEntries2(data, func, il))
			return true;

		return false;
	}
};

class MipsElfRelocationHandler: public RelocationHandler
{
public:

	bool GetGpAddr(Ref<BinaryView> view, int32_t& gpAddr)
	{
		auto sym = view->GetSymbolByRawName("_gp");
		if (!sym)
			sym = view->GetSymbolByRawName("__gnu_local_gp");
		if (!sym)
			return false;
		gpAddr = (int32_t)sym->GetAddress();
		return true;
	}

	virtual bool ApplyRelocation(Ref<BinaryView> view, Ref<Architecture> arch, Ref<Relocation> reloc, uint8_t* dest, size_t len) override
	{
		if (len < 4)
			return false;

		auto info = reloc->GetInfo();
		auto addr = reloc->GetAddress();
		auto symbol = reloc->GetSymbol();
		uint64_t target = reloc->GetTarget() + info.addend;

		int32_t gpAddr = 0;
		uint64_t* dest64 = (uint64_t*)dest;
		uint32_t* dest32 = (uint32_t*)dest;
		auto swap = [&arch](uint32_t x) { return (arch->GetEndianness() == LittleEndian) ? x : bswap32(x); };
		auto swap64 = [&arch](uint64_t x) { return (arch->GetEndianness() == LittleEndian) ? x : bswap64(x); };
		uint32_t inst = swap(dest32[0]);
		uint64_t inst64 = swap64(dest64[0]);

		switch (info.nativeType)
		{
		case R_MIPS_JUMP_SLOT:
		case R_MIPS_COPY:
			dest32[0] = swap((uint32_t)target);
			break;
		case R_MIPS64_COPY:
			dest64[0] = swap64(target);
			break;
		case R_MIPS_32:
			dest32[0] = swap((uint32_t)(inst + target));
			break;
		case R_MIPS_64:
			dest64[0] = swap64(inst64 + target);
			break;
		case R_MIPS_HIGHEST:
		{
			dest64[0] = swap64(inst64 & 0xffff0000ffffffff) | (((target + 0x800080008000) >> 16) & 0xffff00000000 );
			break;
		}
		case R_MIPS_HIGHER:
		{
			dest64[0] = swap64(inst64 & 0xffff0000ffffffff) | (((target + 0x80008000)) & 0xffff00000000 );
			break;
		}
		case R_MIPS_HI16:
		{
			// Find the first _LO16 in the list of relocations
			BNRelocationInfo* cur = info.next;
			while (cur && (cur->nativeType != R_MIPS_LO16))
				cur = cur->next;

			if (cur)
			{
				uint32_t inst2 = *(uint32_t*)(cur->relocationDataCache);
				Instruction instruction;
				memset(&instruction, 0, sizeof(instruction));
				auto version = arch->GetAddressSize() == 8 ? MIPS_64 : MIPS_32;
				if (Architecture::GetByName("r5900l") == arch)
					version = MIPS_R5900;
				if (mips_decompose(&inst2, sizeof(uint32_t), &instruction,
					version, cur->address, arch->GetEndianness(), DECOMPOSE_FLAGS_PSEUDO_OP))
					break;

				int32_t immediate = swap(inst2) & 0xffff;

				// ADDIU and LW has a signed immediate we have to subtract
				if (instruction.operation == MIPS_ADDIU)
					immediate = instruction.operands[2].immediate;
				else if (instruction.operation == MIPS_LW)
					immediate = instruction.operands[1].immediate;
				uint32_t ahl = ((inst & 0xffff) << 16) + immediate;

				// ((AHL + S) – (short)(AHL + S)) >> 16
				dest32[0] = swap((uint32_t)(
					(inst & ~0xffff) |
					(((ahl + target) - (short)(ahl + target)) >> 16)
				));
			}
			else
			{
				LogError("No corresponding R_MIPS_LO16 relocation for R_MIPS_HI16 relocation");
			}
			break;
		}
		case R_MIPS_LO16:
		{
			uint32_t ahl = ((inst & 0xffff) + target) & 0xffff;
			dest32[0] = swap((inst & ~0xffff) | (ahl & 0xffff));
			break;
		}
		case R_MIPS_26:
		{
			// ((A << 2) | (P & 0xf0000000) + S) >> 2
			uint32_t A = (inst & ~0xfc000000) << 2;
			uint32_t P = (uint32_t)addr;
			uint32_t S = (uint32_t)target;
			uint32_t realTarget = (A | (P & 0xf0000000)) + S;
			dest32[0] = swap(((realTarget >> 2) & ~0xfc000000) | (inst & 0xfc000000));
			break;
		}
		case R_MIPS_GOT16:
		case R_MIPS_GPREL16:
		case R_MIPS_CALL16:
		{
			if (!GetGpAddr(view, gpAddr))
				break;
			int32_t vRel16 = (int32_t)(target - gpAddr);
			dest32[0] = swap((inst & ~0xffff) | (vRel16 & 0xffff));
			break;
		}
		case R_MIPS_REL32:
		{
			uint32_t originalValue = inst;
			uint64_t displacement = target;
			dest32[0] = swap((uint32_t)(originalValue + displacement));
			break;
		}
		case (R_MIPS_64 << 8) | R_MIPS_REL32:
		{
			uint64_t originalValue = inst64;
			uint64_t displacement = target;
			dest64[0] = swap64(originalValue + displacement);
			break;
		}
		case R_MIPS_LITERAL:
		case R_MIPS_GPREL32:
		{
			if (!GetGpAddr(view, gpAddr))
				break;
			int32_t vRel32 = (int32_t)(target - gpAddr);
			dest32[0] = swap(vRel32);
			break;
		}
		case R_MIPS_VCALLMS:
			break;
		default:
			break;
		}

		return true;
	}

	virtual bool GetRelocationInfo(Ref<BinaryView> view, Ref<Architecture> arch, vector<BNRelocationInfo>& result) override
	{
		(void)view; (void)arch;
		for (size_t i = 0; i < result.size(); i++)
		{
			result[i].type = StandardRelocationType;
			result[i].size = 4;
			result[i].pcRelative = false;
			result[i].dataRelocation = true;
			switch (result[i].nativeType)
			{
			case R_MIPS_NONE:
			case R_MIPS_JALR: // Note: optimization hint that can safely be ignored TODO: link-time mutable opcode bytes
				result[i].type = IgnoredRelocation;
				break;
			case R_MIPS_COPY:
			case R_MIPS64_COPY:
				result[i].type = ELFCopyRelocationType;
				break;
			case R_MIPS_JUMP_SLOT:
				result[i].type = ELFJumpSlotRelocationType;
				break;
			case R_MIPS_HI16:
				result[i].dataRelocation = false;
				result[i].pcRelative = false;
				// MIPS_HI16 relocations usually come before multiple MIPS_LO16 relocations. But, this is not always
				// the case. Some binaries have MIPS_HI16 relocations after an associated MIPS_LO16 relocation.
				for (size_t j = 0; j < result.size(); j++)
				{
					if (result[j].nativeType == R_MIPS_LO16 && result[j].symbolIndex == result[i].symbolIndex)
					{
						result[j].type = StandardRelocationType;
						result[j].size = 4;
						result[j].pcRelative = false;
						result[j].dataRelocation = false;
						result[i].next = new BNRelocationInfo(result[j]);
						break;
					}
				}

				break;
			case R_MIPS_LO16:
				result[i].pcRelative = false;
				result[i].dataRelocation = false;
				break;
			case R_MIPS_26:
				result[i].pcRelative = true;
				result[i].dataRelocation = false;
				break;
			case R_MIPS_GOT16:
			case R_MIPS_GPREL16:
			case R_MIPS_CALL16:
			case R_MIPS_GPREL32:
			{
				// Note: GP addr not avaiable pre-view-finalization, however symbol may exist
				int32_t gpAddr;
				if (!GetGpAddr(view, gpAddr))
				{
					result[i].type = UnhandledRelocation;
					LogWarn("Unsupported relocation type: %s : Unable to locate _gp symbol.", GetRelocationString((ElfMipsRelocationType)result[i].nativeType));
				}
				break;
			}
			case R_MIPS_32:
			case R_MIPS_64:
				break;
			case (R_MIPS_64 << 8) | R_MIPS_REL32:
			case R_MIPS_REL32:
				break;
			case R_MIPS_HIGHER:
			case R_MIPS_HIGHEST:
				break;
			case R_MIPS_VCALLMS:
				break;
			case R_MIPS_LITERAL:
				break;
			default:
				result[i].type = UnhandledRelocation;
				LogWarn("Unsupported relocation type: %" PRIu64 " (%s) @0x%" PRIx64, result[i].nativeType,
					GetRelocationString((ElfMipsRelocationType)result[i].nativeType), result[i].address);
			}
		}

		return true;
	}

	virtual size_t GetOperandForExternalRelocation(const uint8_t* data, uint64_t addr, size_t length,
		Ref<LowLevelILFunction> il, Ref<Relocation> relocation) override
	{
		(void)data;
		(void)addr;
		(void)length;
		(void)il;
		auto info = relocation->GetInfo();
		size_t result;

		switch (info.nativeType)
		{
			case R_MIPS_HI16:
			case R_MIPS_LO16:
			case R_MIPS_CALL16:
			case R_MIPS_GOT16:
			case R_MIPS_HIGHER:
			case R_MIPS_HIGHEST:
				result = BN_NOCOERCE_EXTERN_PTR;
				break;
			default:
				result = BN_AUTOCOERCE_EXTERN_PTR;
				break;
		}

		return result;
	}
};

static void InitMipsSettings()
{
	Ref<Settings> settings = Settings::Instance();

	settings->RegisterSetting("arch.mips.disassembly.pseudoOps",
			R"({
			"title" : "MIPS Disassembly Pseudo-Op",
			"type" : "boolean",
			"default" : true,
			"description" : "Enable use of pseudo-op instructions in MIPS disassembly."
			})");
}

//BINARY_VIEW
static Ref<Platform> ElfFlagsRecognize(BinaryView* view, Metadata* metadata)
{
	Ref<Metadata> abiMetadata = metadata->Get("EI_OSABI");
	if (!abiMetadata || !abiMetadata->IsUnsignedInteger())
		return nullptr;

	uint64_t abi = abiMetadata->GetUnsignedInteger();
	if (abi != 0 && abi != 3)
		return nullptr;

	Ref<Metadata> flagsMetadata = metadata->Get("e_flags");
	if (!flagsMetadata || !flagsMetadata->IsUnsignedInteger())
		return nullptr;

	uint64_t flagsValue = flagsMetadata->GetUnsignedInteger();
	uint8_t machineVariant = (flagsValue >> 16) & 0xff;

	switch (machineVariant)
	{
		case 0x8b:	// EF_MIPS_MACH_OCTEON
		case 0x8d:	// EF_MIPS_MACH_OCTEON2
		case 0x8e:	// EF_MIPS_MACH_OCTEON3
			LogInfo("ELF flags 0x%08" PRIx64 " machine variant 0x%02x: using cavium architecture", flagsValue, machineVariant);
			return Platform::GetByName("linux-cnmips64");
		case 0x92:  // E_MIPS_MACH_5900
			LogInfo("ELF flags 0x%08" PRIx64 " machine variant 0x%02x: using R5900 architecture", flagsValue, machineVariant);
			return Platform::GetByName("r5900l");
		default:
			return nullptr;
	}
}

extern "C"
{
	BN_DECLARE_CORE_ABI_VERSION

#ifndef DEMO_EDITION
	BINARYNINJAPLUGIN void CorePluginDependencies()
	{
		AddOptionalPluginDependency("view_elf");
		AddOptionalPluginDependency("view_pe");
	}
#endif

	BINARYNINJAPLUGIN bool CorePluginInit()
	{
		InitMipsSettings();

		Architecture* mipsel = new MipsArchitecture("mipsel32", MIPS_32, LittleEndian, 32);
		Architecture* mipseb = new MipsArchitecture("mips32", MIPS_32, BigEndian, 32);
		Architecture* mips3 = new MipsArchitecture("mips3", MIPS_3, BigEndian, 32);
		Architecture* mips3el = new MipsArchitecture("mipsel3", MIPS_3, LittleEndian, 32);
		Architecture* mips64el = new MipsArchitecture("mipsel64", MIPS_64, LittleEndian, 64);
		Architecture* mips64eb = new MipsArchitecture("mips64", MIPS_64, BigEndian, 64);
		Architecture* cnmips64eb = new MipsArchitecture("cavium-mips64", MIPS_64, BigEndian, 64, DECOMPOSE_FLAGS_CAVIUM);
		Architecture* r5900l = new MipsArchitecture("r5900l", MIPS_R5900, LittleEndian, 32);
		// R5900 should only be Little-Endian, so until someone complains, I'm leaving the Big-Endian variant disabled.
		// Architecture* r5900b = new MipsArchitecture("r5900b", MIPS_R5900, BigEndian, 32);

		Architecture::Register(mipsel);
		Architecture::Register(mipseb);
		Architecture::Register(r5900l);
		// Architecture::Register(r5900b);
		Architecture::Register(mips3);
		Architecture::Register(mips3el);
		Architecture::Register(mips64el);
		Architecture::Register(mips64eb);
		Architecture::Register(cnmips64eb);

		/* calling conventions */
		MipsO32CallingConvention* o32LE = new MipsO32CallingConvention(mipsel);
		MipsO32CallingConvention* o32BE = new MipsO32CallingConvention(mipseb);
		MipsN64CallingConvention* n64LE = new MipsN64CallingConvention(mips64el);
		MipsN64CallingConvention* n64BE = new MipsN64CallingConvention(mips64eb);
		MipsN64CallingConvention* n64BEc = new MipsN64CallingConvention(cnmips64eb);
		MipsPS2CallingConvention* ps2LE = new MipsPS2CallingConvention(r5900l);
		// MipsPS2CallingConvention* ps2BE = new MipsPS2CallingConvention(r5900b);

		mipseb->RegisterCallingConvention(o32BE);
		mipseb->SetDefaultCallingConvention(o32BE);
		mipsel->RegisterCallingConvention(o32LE);
		mipsel->SetDefaultCallingConvention(o32LE);
		mips3->RegisterCallingConvention(o32BE);
		mips3->SetDefaultCallingConvention(o32BE);
		mips3el->RegisterCallingConvention(o32LE);
		mips3el->SetDefaultCallingConvention(o32LE);
		mips64el->RegisterCallingConvention(n64LE);
		mips64el->SetDefaultCallingConvention(n64LE);
		mips64eb->RegisterCallingConvention(n64BE);
		mips64eb->SetDefaultCallingConvention(n64BE);
		cnmips64eb->RegisterCallingConvention(n64BEc);
		cnmips64eb->SetDefaultCallingConvention(n64BEc);
		r5900l->RegisterCallingConvention(ps2LE);
		r5900l->SetDefaultCallingConvention(ps2LE);
		// r5900b->RegisterCallingConvention(ps2BE);
		// r5900b->SetDefaultCallingConvention(ps2BE);

		MipsLinuxSyscallCallingConvention* linuxSyscallBE = new MipsLinuxSyscallCallingConvention(mipseb);
		MipsLinuxSyscallCallingConvention* linuxSyscallLE = new MipsLinuxSyscallCallingConvention(mipsel);
		mipseb->RegisterCallingConvention(linuxSyscallBE);
		mipsel->RegisterCallingConvention(linuxSyscallLE);
		MipsLinuxSyscallCallingConvention* linuxSyscallBE3 = new MipsLinuxSyscallCallingConvention(mips3);
		MipsLinuxSyscallCallingConvention* linuxSyscallLE3 = new MipsLinuxSyscallCallingConvention(mips3el);
		mips3->RegisterCallingConvention(linuxSyscallBE3);
		mips3el->RegisterCallingConvention(linuxSyscallLE3);
		MipsLinuxSyscallCallingConvention* linuxSyscallr5900LE = new MipsLinuxSyscallCallingConvention(r5900l);
		// MipsLinuxSyscallCallingConvention* linuxSyscallr5900BE = new MipsLinuxSyscallCallingConvention(r5900b);
		r5900l->RegisterCallingConvention(linuxSyscallr5900LE);
		// r5900b->RegisterCallingConvention(linuxSyscallr5900BE);

		mipsel->RegisterCallingConvention(new MipsLinuxRtlResolveCallingConvention(mipsel));
		mipseb->RegisterCallingConvention(new MipsLinuxRtlResolveCallingConvention(mipseb));
		r5900l->RegisterCallingConvention(new MipsLinuxRtlResolveCallingConvention(r5900l));
		// r5900b->RegisterCallingConvention(new MipsLinuxRtlResolveCallingConvention(r5900b));
		mips3->RegisterCallingConvention(new MipsLinuxRtlResolveCallingConvention(mips3));
		mips3el->RegisterCallingConvention(new MipsLinuxRtlResolveCallingConvention(mips3el));
		mips64el->RegisterCallingConvention(new MipsLinuxRtlResolveCallingConvention(mips64el));
		mips64eb->RegisterCallingConvention(new MipsLinuxRtlResolveCallingConvention(mips64eb));
		cnmips64eb->RegisterCallingConvention(new MipsLinuxRtlResolveCallingConvention(cnmips64eb));

		/* function recognizers */
		mipsel->RegisterFunctionRecognizer(new MipsImportedFunctionRecognizer());
		mipseb->RegisterFunctionRecognizer(new MipsImportedFunctionRecognizer());
		mips3->RegisterFunctionRecognizer(new MipsImportedFunctionRecognizer());
		mips3el->RegisterFunctionRecognizer(new MipsImportedFunctionRecognizer());

		mipseb->RegisterRelocationHandler("ELF", new MipsElfRelocationHandler());
		mipsel->RegisterRelocationHandler("ELF", new MipsElfRelocationHandler());
		mips3->RegisterRelocationHandler("ELF", new MipsElfRelocationHandler());
		mips3el->RegisterRelocationHandler("ELF", new MipsElfRelocationHandler());
		mips64eb->RegisterRelocationHandler("ELF", new MipsElfRelocationHandler());
		mips64el->RegisterRelocationHandler("ELF", new MipsElfRelocationHandler());
		r5900l->RegisterRelocationHandler("ELF", new MipsElfRelocationHandler());
		// r5900b->RegisterRelocationHandler("ELF", new MipsElfRelocationHandler());
		cnmips64eb->RegisterRelocationHandler("ELF", new MipsElfRelocationHandler());

		// Register the architectures with the binary format parsers so that they know when to use
		// these architectures for disassembling an executable file

		/* since elfXX_hdr.e_machine == EM_MIPS (8) on both mips and mips64, we adopt the following
		   convention to disambiguate: shift in elf64_hdr.e_ident[EI_CLASS]: */
		#define EM_MIPS (8)
		#define EI_CLASS_32 (1)
		#define EI_CLASS_64 (2)
		#define ARCH_ID_MIPS32 ((EI_CLASS_32<<16)|EM_MIPS) /* 0x10008 */
		#define ARCH_ID_MIPS64 ((EI_CLASS_64<<16)|EM_MIPS) /* 0x20008 */
		BinaryViewType::RegisterArchitecture("ELF", ARCH_ID_MIPS64, LittleEndian, mips64el);
		BinaryViewType::RegisterArchitecture("ELF", ARCH_ID_MIPS64, BigEndian, mips64eb);
		BinaryViewType::RegisterArchitecture("ELF", ARCH_ID_MIPS32, LittleEndian, mipsel);
		BinaryViewType::RegisterArchitecture("ELF", ARCH_ID_MIPS32, BigEndian, mipseb);

		Ref<BinaryViewType> elf = BinaryViewType::GetByName("ELF");
		if (elf)
		{
			elf->RegisterPlatformRecognizer(ARCH_ID_MIPS64, LittleEndian, ElfFlagsRecognize);
			elf->RegisterPlatformRecognizer(ARCH_ID_MIPS64, BigEndian, ElfFlagsRecognize);
			elf->RegisterPlatformRecognizer(ARCH_ID_MIPS32, LittleEndian, ElfFlagsRecognize); // R5900
		}

		BinaryViewType::RegisterArchitecture("PE", 0x166, LittleEndian, mipsel);
		return true;
	}
}
