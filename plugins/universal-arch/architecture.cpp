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
	UniversalCallingConvention(Architecture* arch, const char* const name): CallingConvention(arch, name)
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

	virtual bool IsEligibleForHeuristics() override
	{
		return false;
	}

	virtual bool IsStackReservedForArgumentRegisters() override
	{
		return true;
	}
};

class UniversalImportedFunctionRecognizer: public FunctionRecognizer
{
public:
	virtual bool RecognizeLowLevelIL(BinaryView* data, Function* func, LowLevelILFunction* il) override
	{
        (void)data;
        (void)func;
        (void)il;
		return false;
	}
};

class UniversalElfRelocationHandler: public RelocationHandler
{
public:

	virtual bool ApplyRelocation(Ref<BinaryView> view, Ref<Architecture> arch, Ref<Relocation> reloc, uint8_t* dest, size_t len) override
	{
        (void)view;
        (void)arch;
        (void)reloc;
        (void)dest;
        (void)len;
		return false;
	}

	virtual bool GetRelocationInfo(Ref<BinaryView> view, Ref<Architecture> arch, vector<BNRelocationInfo>& result) override
	{
		(void)view;
        (void)arch;
        (void)result;
		return false;
	}

	virtual size_t GetOperandForExternalRelocation(const uint8_t* data, uint64_t addr, size_t length,
		Ref<LowLevelILFunction> il, Ref<Relocation> relocation) override
	{
		(void)data;
		(void)addr;
		(void)length;
		(void)il;
        (void)relocation;
		return 0U;
	}
};

static Ref<Platform> ElfUniversalRecognizer(BinaryView* view, Metadata* metadata)
{
    (void)view;
    (void)metadata;
    return nullptr;
}

extern "C"
{
	BN_DECLARE_CORE_ABI_VERSION

	BINARYNINJAPLUGIN void CorePluginDependencies()
	{
		AddOptionalPluginDependency("view_elf");
		AddOptionalPluginDependency("view_pe");
	}

	BINARYNINJAPLUGIN bool CorePluginInit()
	{
		Architecture* architecture = new UniversalArchitecture("mipsel32");

		Architecture::Register(architecture);

		/* calling conventions */
        CallingConvention arch_convention = new UniversalCallingConvention(architecture, "arch");
        architecture->RegisterCallingConvention(arch_convention);
        architecture->RegisterCallingConvention(new UniversalCallingConvention(architecture, "linux-syscall"));
		architecture->RegisterCallingConvention(new UniversalCallingConvention(architecture, "linux-rtl-resolve"));
		architecture->SetDefaultCallingConvention(arch_convention);

		/* function recognizers */
		architecture->RegisterFunctionRecognizer(new UniversalImportedFunctionRecognizer());
        architecture->RegisterRelocationHandler("ELF", new UniversalElfRelocationHandler());

		// Register the architectures with the binary format parsers so that they know when to use
		// these architectures for disassembling an executable file

		/* since elfXX_hdr.e_machine == EM_MIPS (8) on both mips and mips64, we adopt the following
		   convention to disambiguate: shift in elf64_hdr.e_ident[EI_CLASS]: */
		#define EM_MIPS (8)
		#define EI_CLASS_32 (1)
		#define EI_CLASS_64 (2)
		#define ARCH_ID_MIPS32 ((EI_CLASS_32<<16)|EM_MIPS) /* 0x10008 */
		#define ARCH_ID_MIPS64 ((EI_CLASS_64<<16)|EM_MIPS) /* 0x20008 */
		BinaryViewType::RegisterArchitecture("ELF", ARCH_ID_MIPS32, BigEndian, architecture);
		BinaryViewType::RegisterArchitecture("PE", 0x166, BigEndian, architecture);

		Ref<BinaryViewType> elf = BinaryViewType::GetByName("ELF");
		if (elf)
		{
			elf->RegisterPlatformRecognizer(ARCH_ID_MIPS32, BigEndian, ElfUniversalRecognizer);
		}

		return true;
	}
}
