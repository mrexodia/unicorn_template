#include <cstdlib>
#include <cstdint>
#include <vector>
#include <map>
#include <stdexcept>
#include <cassert>
#include <type_traits>
#include <string>
#include <algorithm>

#include <unicorn/unicorn.h>
#include <capstone/capstone.h>
#include <keystone/keystone.h>

static std::map<std::string, uint64_t> global_symbols;

static bool sym_resolver(const char* symbol, uint64_t* value)
{
	auto itr = global_symbols.find(symbol);
	if (itr != global_symbols.end())
	{
		*value = itr->second;
		return true;
	}
	return false;
}

static std::vector<uint8_t> assemble(uint64_t address, const char* asm_text)
{
	ks_engine* ks = nullptr;
	if (ks_open(KS_ARCH_X86, KS_MODE_64, &ks) != KS_ERR_OK)
		throw std::runtime_error("ks_open failed");

	if (ks_option(ks, KS_OPT_SYM_RESOLVER, (size_t)sym_resolver) != KS_ERR_OK)
		throw std::runtime_error(ks_strerror(ks_errno(ks)));

	unsigned char* encoding = nullptr;
	size_t encoding_size = 0;
	size_t count = 0;
	if (ks_asm(ks, asm_text, address, &encoding, &encoding_size, &count))
		throw std::runtime_error(ks_strerror(ks_errno(ks)));

	std::vector<uint8_t> code;
	code.resize(encoding_size);
	memcpy(code.data(), encoding, code.size());

	ks_close(ks);

	return code;
}

static std::string disassemble(uint64_t address, std::vector<uint8_t> code)
{
	csh cs;
	if (cs_open(CS_ARCH_X86, CS_MODE_64, &cs) != CS_ERR_OK)
		throw std::runtime_error("cs_open failed");

	auto insn = cs_malloc(cs);

	std::string result;
	const uint8_t* code_ptr = code.data();
	size_t code_size = code.size();
	while (cs_disasm_iter(cs, &code_ptr, &code_size, &address, insn))
	{
		if (!result.empty())
			result += '\n';

		// Print address
		char address_text[32] = "";
		sprintf_s(address_text, "0x%llx ", address - insn->size);
		result += address_text;

		// Print instruction
		result += insn->mnemonic;
		if (*insn->op_str)
		{
			result += ' ';
			result += insn->op_str;
		}
	}

	cs_free(insn, 1);

	cs_close(&cs);

	return result;
}

static std::string to_hex(const std::vector<uint8_t>& data)
{
	std::string result;
	for (auto ch : data)
	{
		if (!result.empty())
			result += ' ';
		char blah[32] = "";
		sprintf_s(blah, "%02X", ch);
		result += blah;
	}
	return result;
}

#define uc_assert(x) \
{ \
	auto err = (x); \
	if(err != UC_ERR_OK) \
	{ \
		throw std::runtime_error(std::string(#x) + " failed: " + uc_strerror(err)); \
	} \
}

static constexpr size_t page_size = 0x1000;

class DumbPoolAllocator
{
	uint64_t base = 0;
	uint64_t size = 0;

	uint64_t start_ptr = 0;
	uint64_t end_ptr = 0;

	std::map<uint64_t, std::pair<size_t, std::string>> info;

public:
	DumbPoolAllocator(DumbPoolAllocator&) = delete;
	DumbPoolAllocator(DumbPoolAllocator&&) = delete;

	DumbPoolAllocator(uint64_t base, size_t size)
		: base(base), size(size)
	{
		start_ptr = base;
		end_ptr = start_ptr + size;
	}

	DumbPoolAllocator& start(uint64_t* base, size_t size, const std::string& name)
	{
		size = (size + (page_size - 1)) & ~(page_size - 1);
		*base = start_ptr;
		start_ptr += size;
		if (start_ptr > end_ptr)
			throw std::runtime_error("Out of kernel pool memory");
		info[*base] = { size, name };
		return *this;
	}

	DumbPoolAllocator& end(uint64_t* base, size_t size, const std::string& name)
	{
		size = (size + (page_size - 1)) & ~(page_size - 1);
		end_ptr -= size;
		*base = end_ptr;
		if (start_ptr > end_ptr)
			throw std::runtime_error("Out of kernel pool memory");
		info[*base] = { size, name };
		return *this;
	}

	uint64_t pool_start(uint64_t* size = nullptr) const
	{
		if (size != nullptr)
			*size = pool_size();
		return base;
	}

	size_t pool_size() const
	{
		return size;
	}

	void dump_info() const
	{
		for (const auto& [base, n] : info)
		{
			const auto& [size, name] = n;
			printf("0x%016llx[0x%08llx] %s\n", base, size, name.c_str());
		}
	}

	std::pair<size_t, std::string> const* find_info(uint64_t address)
	{
		address &= ~(page_size - 1);
		auto itr = info.lower_bound(address);
		if (itr == info.end())
			return nullptr;
		if (itr->first == address)
			return &itr->second;
		if (itr == info.begin())
			return nullptr;
		itr--;
		if (address >= itr->first && address < itr->first + itr->second.first)
			return &itr->second;
		return nullptr;
	}
};

/*
These values are copied from a live Windows 10 VM.

References:
- https://wiki.osdev.org/Global_Descriptor_Table
- daax and lauree for helping me understand this stuff

Selector 0x10 (index 2)
UInt64: 0x00209b0000000000 => kernel CS
  Base: 0x0000000000000000
 Limit: 0x0000000000000000
  Type: 11 <- code execute+read+access
	 S: 1
   DPL: 0 <- ring0
	 P: 1
	 L: 1 <- 64-bit
	DB: 0

Selector 0x18 (index 3) => kernel SS
UInt64: 0x0040930000000000
  Base: 0x0000000000000000
 Limit: 0x0000000000000000
  Type: 3 <- data read+write+access
	 S: 1
   DPL: 0 <- ring0
	 P: 1
	 L: 0
	DB: 1 <- 32-bit

Selector 0x20 (index 4) => user wow64 CS
UInt64: 0x00cffb000000ffff
  Base: 0x0000000000000000
 Limit: 0x00000000ffffffff
  Type: 11 <- code execute+read+access
	 S: 1
   DPL: 3 <- ring3
	 P: 1
	 L: 0
	DB: 1 <- 32-bit

Selector 0x28 (index 5) => kernel DS,ES,GS + user SS
UInt64: 0x00cff3000000ffff
  Base: 0x0000000000000000
 Limit: 0x00000000ffffffff
  Type: 3 <- data read+write+access
	 S: 1
   DPL: 3 <- ring3
	 P: 1
	 L: 0
	DB: 1 <- 32-bit

Selector 0x30 (index 6) => user CS
UInt64: 0x0020fb0000000000
  Base: 0x0000000000000000
 Limit: 0x0000000000000000
  Type: 11 <- code execute+read+access
	 S: 1
   DPL: 3 <- ring3
	 P: 1
	 L: 1 <- 64-bit
	DB: 0

Selector 0x40 (index 8) => TSS
UInt64: 0x6d008b9630000067
  Base: 0xfffff8076d963000
 Limit: 0x0000000000000067
  Type: 11 <- 64-bit TSS (Busy)
	 S: 0 <- system segment
   DPL: 0 <- ring0
	 P: 1
	 L: 0
	DB: 0

Selector 0x50 (index 10) => kernel FS
UInt64: 0x0040f30000003c00
  Base: 0x0000000000000000
 Limit: 0x0000000000003c00
  Type: 3 <- data read+write+access
	 S: 1
   DPL: 3 <- ring3
	 P: 1
	 L: 0
	DB: 1 <- 32-bit
*/
static std::vector<uint64_t> windows_gdt =
{
	0x0000000000000000, // NULL
	0x0000000000000000,
	0x00209b0000000000, // kernel CS
	0x0040930000000000, // kernel SS
	0x00cffb000000ffff, // user wow64 CS
	0x00cff3000000ffff, // kernel DS,ES,GS + user SS
	0x0020fb0000000000, // user CS
	0x0000000000000000,
	0x6d008b9630000067, // TSS (base: 0xfffff8076d963000)
	0x00000000fffff807,
	0x0040f30000003c00, // kernel FS
};

struct SegmentRegisters
{
	uint16_t cs = 0;
	uint16_t ss = 0;
	uint16_t ds = 0;
	uint16_t es = 0;
	uint16_t fs = 0;
	uint16_t gs = 0;
};

static SegmentRegisters windows_kernel_segment = { 0x10, 0x18, 0x2B, 0x2B, 0x53, 0x2B };
static SegmentRegisters windows_user_segment = { 0x33, 0x2B, 0x2B, 0x2B, 0x53, 0x2B };
static SegmentRegisters windows_wow64_segment = { 0x23, 0x2B, 0x2B, 0x2B, 0x53, 0x2B };

static constexpr size_t kernel_stack_size = 0x5000; // JustMagic: should be 13kb
static constexpr size_t tss_stack_size = page_size; // TODO: made up number
static constexpr size_t kernel_code_size = page_size;
static constexpr size_t idt_code_size = page_size;
static constexpr size_t end_code_size = page_size;
static constexpr size_t ret_offset = 0x80;
static constexpr size_t iretq_offset = 0x100;
static constexpr size_t iretd_offset = 0x101;

static uint64_t windows_tss_base;
static uint64_t windows_gdt_base;
static uint64_t windows_idt_base;
static uint64_t kernel_stack;
static uint64_t kernel_code;
static uint64_t kernel_teb;
static uint64_t tss_stack;
static uint64_t idt_code;
static uint64_t end_code;

static DumbPoolAllocator kernel_pool(0xfffff8076d963000 - 0x963000, 0x964000);
static uint64_t kernel_range_size;
static uint64_t kernel_range_start = kernel_pool
.end(&windows_tss_base, page_size, "tss")
.end(&windows_gdt_base, page_size, "gdt")
.end(&windows_idt_base, page_size, "idt")
.end(&kernel_stack, kernel_stack_size, "kernel stack")
.end(&tss_stack, tss_stack_size, "tss stack")
.start(&kernel_code, kernel_code_size, "kernel code")
.start(&idt_code, idt_code_size, "idt code")
.start(&end_code, end_code_size, "end code")
.pool_start(&kernel_range_size);

#pragma pack(push, 1)

// Information: https://wiki.osdev.org/IDT#Structure_on_x86-64
// Source: https://github.com/ntdiff/headers/blob/ec39df2a0d463404b8da0facdc4bebd2e838e40f/Win7_SP1/x64/System32/ndis.sys/Standalone/_KIDTENTRY64.h
// Some interrupt names: https://gitlab.com/bztsrc/minidbg/-/blob/master/x86_64/dbgc.c#L42-44
// Another interesting post: https://www.alex-ionescu.com/?p=340
typedef union _KIDTENTRY64
{
	union
	{
		struct
		{
			/* 0x0000 */ unsigned short OffsetLow;
			/* 0x0002 */ unsigned short Selector; // Code segment in the GDT
			struct /* bitfield */
			{
				/* 0x0004 */ unsigned short IstIndex : 3; /* bit position: 0 */ // If the bits are all set to zero, the Interrupt Stack Table is not used.
				/* 0x0004 */ unsigned short Reserved0 : 5; /* bit position: 3 */
				/* 0x0004 */ unsigned short Type : 5; /* bit position: 8 */ // E: 64-bit interrupt gate, 0xF: 64-bit trap gate
				/* 0x0004 */ unsigned short Dpl : 2; /* bit position: 13 */ // A 2-bit value which defines the CPU Privilege Levels which are allowed to access this interrupt via the INT instruction. Hardware interrupts ignore this mechanism.
				/* 0x0004 */ unsigned short Present : 1; /* bit position: 15 */ // Present bit. Must be set (1) for the descriptor to be valid.
			}; /* bitfield */
			/* 0x0006 */ unsigned short OffsetMiddle;
			/* 0x0008 */ unsigned long OffsetHigh;
			/* 0x000c */ unsigned long Reserved1;
		}; /* size: 0x0010 */
		/* 0x0000 */ unsigned __int64 Alignment;
	}; /* size: 0x0010 */
} KIDTENTRY64, * PKIDTENTRY64; /* size: 0x0010 */
static_assert(sizeof(KIDTENTRY64) == 0x10, "");

/* Reference: https://wiki.osdev.org/Task_State_Segment
0: kd> dt nt!_KTSS64 0xfffff8014af63000
   +0x000 Reserved0        : 0
   +0x004 Rsp0             : 0xfffff801`4af6ec90
   +0x00c Rsp1             : 0
   +0x014 Rsp2             : 0
   +0x01c Ist              : [8] 0
   +0x05c Reserved1        : 0
   +0x064 Reserved2        : 0
   +0x066 IoMapBase        : 0x68
0: kd> dx -id 0,0,ffffbe8a7827f040 -r1 (*((ntkrnlmp!unsigned __int64 (*)[8])0xfffff8014af6301c))
(*((ntkrnlmp!unsigned __int64 (*)[8])0xfffff8014af6301c))                 [Type: unsigned __int64 [8]]
	[0]              : 0x0 [Type: unsigned __int64]
	[1]              : 0xfffff8014af8b000 [Type: unsigned __int64]
	[2]              : 0xfffff8014af99000 [Type: unsigned __int64]
	[3]              : 0xfffff8014af92000 [Type: unsigned __int64]
	[4]              : 0xfffff8014afa0000 [Type: unsigned __int64]
	[5]              : 0x0 [Type: unsigned __int64]
	[6]              : 0x0 [Type: unsigned __int64]
	[7]              : 0x0 [Type: unsigned __int64]

0: kd> db 0xfffff8014af63068 L20
fffff801`4af63068  00 00 00 00 00 00 00 00-00 a0 c7 42 01 f8 ff ff  ...........B....
fffff801`4af63078  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
*/
typedef struct _KTSS64 // Size=0x68 (Id=198)
{
	unsigned long Reserved0;// Offset=0x0 Size=0x4
	unsigned long long Rsp0;// Offset=0x4 Size=0x8
	unsigned long long Rsp1;// Offset=0xc Size=0x8
	unsigned long long Rsp2;// Offset=0x14 Size=0x8
	unsigned long long Ist[8];// Offset=0x1c Size=0x40
	unsigned long long Reserved1;// Offset=0x5c Size=0x8
	unsigned short Reserved2;// Offset=0x64 Size=0x2
	// If the I/O bit map base address is greater than or equal to the TSS segment limit, there is no I/O permission map,
	// and all I / O instructions generate exceptions when the CPL is greater than the current IOPL.
	unsigned short IoMapBase;// Offset=0x66 Size=0x2 -> 0x68 on Windows, likely that means it's disabled?
} KTSS64, * PKTSS64;
static_assert(sizeof(_KTSS64) == 0x68, "");

#pragma pack(pop)

struct Emulator
{
	uc_engine* uc = nullptr;

	Emulator()
	{
		uc_assert(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
		uc_ctl_exits_enable(uc);
		uc_hook intr_hook;
		uc_hook_add(uc, &intr_hook, UC_HOOK_INTR, s_uc_hook_intr, this, 0, -1);
		uc_hook_add(uc, &intr_hook, UC_HOOK_MEM_INVALID, s_uc_hook_mem, this, 0, -1);
		uc_hook_add(uc, &intr_hook, UC_HOOK_CODE, s_uc_hook_code, this, 0, -1);
		init_kernel();
	}

	void hook_intr(uint32_t intno)
	{
		// Source: https://gitlab.com/bztsrc/minidbg/-/blob/master/x86_64/dbgc.c#L42
		char* exc[] = { "Div zero", "Debug", "NMI", "Breakpoint instruction", "Overflow", "Bound", "Invopcode", "DevUnavail",
		"DblFault", "CoProc", "InvTSS", "SegFault", "StackFault", "GenProt", "PageFault", "Unknown", "Float", "Alignment",
		"MachineCheck", "Double" };
		if (intno > 31)
			printf("Interrupt %02x: IRQ %d\n", intno, intno - 32);
		else
			printf("Exception %02x: %s\n", intno, intno < 20 ? exc[intno] : "Unknown");

		printf("rip: 0x%llx\n", reg_rip());
		printf("rsp: 0x%llx\n", reg_rsp());

		//reg_write(UC_X86_REG_RIP, idt_code);
	}

	bool hook_mem(uc_mem_type type, uint64_t address, int size, int64_t value)
	{
		printf("hook_mem, type: %d, address: 0x%llx[0x%x] = 0x%llx\n", type, address, size, value);
		printf("rip: 0x%llx\n", reg_rip());
		printf("rsp: 0x%llx\n", reg_rsp());
		printf("cs: 0x%04x\n", reg_read<uint16_t>(UC_X86_REG_CS));
		printf("ss: 0x%04x\n", reg_read<uint16_t>(UC_X86_REG_SS));

		//mem_map(address & ~(page_size - 1), page_size); // TODO: unmap this
		//reg_write(UC_X86_REG_RIP, 0xfffff8076d00001bull);
		return false;
	}

	void hook_code(uint64_t address, uint32_t size)
	{
		std::vector<uint8_t> code(size);
		mem_read(address, code.data(), code.size());
		printf("code: 0x%llx[0x%x] = %s, rsp: 0x%llx, cs: %x\n",
			address,
			size,
			to_hex(code).c_str(),
			reg_read<uint64_t>(UC_X86_REG_RSP),
			reg_read<uint16_t>(UC_X86_REG_CS)
		);
	}

	static void s_uc_hook_intr(uc_engine* uc, uint32_t intno, void* user_data)
	{
		return ((Emulator*)user_data)->hook_intr(intno);
	}

	static bool s_uc_hook_mem(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void* user_data)
	{
		return ((Emulator*)user_data)->hook_mem(type, address, size, value);
	}

	static void s_uc_hook_code(uc_engine* uc, uint64_t address, uint32_t size, void* user_data)
	{
		return ((Emulator*)user_data)->hook_code(address, size);
	}

	~Emulator()
	{
		if (uc != nullptr)
		{
			uc_close(uc);
			uc = nullptr;
		}
	}

	void init_kernel()
	{
		// Allocate the kernel memory range
		mem_map(kernel_range_start, kernel_range_size, UC_PROT_READ | UC_PROT_WRITE);

		// GDT
		{
			auto gdt_size = uint32_t(windows_gdt.size() * sizeof(uint64_t));
			mem_write(windows_gdt_base, windows_gdt.data(), gdt_size);
			uc_x86_mmr gdtr = { 0, windows_gdt_base, gdt_size - 1, 0 };
			uc_assert(uc_reg_write(uc, UC_X86_REG_GDTR, &gdtr));
			switch_segment(windows_kernel_segment);
		}

		// TSS
		{
			KTSS64 tss = { 0 };
			tss.Rsp0 = tss_stack + tss_stack_size - 0x100;
			// TODO: tss.Ist
			tss.IoMapBase = 0x68;
			mem_write(windows_tss_base, &tss, sizeof(tss));
		}

		// IDT
		{
			// TODO: this is just a hack for testing a single interrupt handler
			uint64_t handler = idt_code;
			KIDTENTRY64 entry = { 0 };
			entry.OffsetLow = handler & 0xFFFF;
			entry.OffsetMiddle = (handler >> 16) & 0xFFFF;
			entry.OffsetHigh = (handler >> 32) & 0xFFFFFFFF;
			entry.Selector = windows_kernel_segment.cs;
			entry.IstIndex = 0;
			entry.Type = 0xE;
			entry.Dpl = 0;
			entry.Present = 1;
			mem_write(windows_idt_base, &entry, sizeof(entry));
			uc_x86_mmr idtr = { 0, windows_idt_base, 0xFFFF, 0 };
			uc_assert(uc_reg_write(uc, UC_X86_REG_IDTR, &idtr));

			// Create a single interrupt handler
			{
				auto handler = assemble(idt_code, R"ASM(
iretq
)ASM");
				mem_write(idt_code, handler.data(), handler.size());
				mem_protect(idt_code, idt_code_size, UC_PROT_READ | UC_PROT_EXEC);
			}
		}

		// Page for shellcode
		mem_protect(kernel_code, page_size, UC_PROT_READ | UC_PROT_EXEC);

		// Page for end code
		mem_protect(end_code, end_code_size, UC_PROT_READ | UC_PROT_EXEC);
		std::vector<uint8_t> die(end_code_size, 0x90);

		die[ret_offset] = 0xC3; // ret
		die[iretq_offset] = 0x48; // rex.w
		die[iretd_offset] = 0xCF; // iret

		mem_write(end_code, die.data(), die.size());

		// Kernel stack
		{
			mem_protect(kernel_stack, page_size, UC_PROT_NONE);
			auto rsp = kernel_stack + kernel_stack_size - 0x100;
			reg_write(UC_X86_REG_RSP, rsp);
			push(end_code);
			printf("initial rsp: 0x%llx\n", reg_rsp());
		}
	}

	void mem_map(uint64_t address, size_t size, uint32_t prot = UC_PROT_ALL)
	{
		uc_assert(uc_mem_map(uc, address, size, prot));
	}

	void mem_protect(uint64_t address, size_t size, uint32_t prot = UC_PROT_ALL)
	{
		uc_assert(uc_mem_protect(uc, address, size, prot));
	}

	void mem_write(uint64_t address, const void* bytes, size_t size)
	{
		uc_assert(uc_mem_write(uc, address, bytes, size));
	}

	void mem_read(uint64_t address, void* bytes, size_t size)
	{
		uc_assert(uc_mem_read(uc, address, bytes, size));
	}

	void switch_segment(const SegmentRegisters& segment, uint64_t gsbase = -1, uint64_t fsbase = -1)
	{
		reg_write(UC_X86_REG_CS, segment.cs);
		reg_write(UC_X86_REG_SS, segment.ss);
		reg_write(UC_X86_REG_DS, segment.ds);
		reg_write(UC_X86_REG_ES, segment.es);
		reg_write(UC_X86_REG_FS, segment.fs);
		reg_write(UC_X86_REG_GS, segment.gs);

		if (gsbase != -1)
			reg_write(UC_X86_REG_GS_BASE, gsbase);

		if (fsbase != -1)
			reg_write(UC_X86_REG_FS_BASE, fsbase);
	}

	template<typename T>
	T reg_read(uc_x86_reg id)
	{
		static_assert(std::is_integral_v<T>, "");
		T value = 0;
		uc_assert(uc_reg_read(uc, id, &value));
		return value;
	}

	template<typename T>
	void reg_write(uc_x86_reg id, const T& value)
	{
		static_assert(std::is_integral_v<T>, "");
		uc_assert(uc_reg_write(uc, id, &value));
	}

	void push(uint64_t value)
	{
		auto rsp = reg_read<uint64_t>(UC_X86_REG_RSP);
		rsp -= sizeof(uint64_t);
		reg_write(UC_X86_REG_RSP, rsp);

		mem_write(rsp, &value, sizeof(value));
	}

	uint64_t pop()
	{
		auto rsp = reg_read<uint64_t>(UC_X86_REG_RSP);
		uint64_t value = 0;
		mem_read(rsp, &value, sizeof(value));
		reg_write(UC_X86_REG_RSP, rsp + sizeof(uint64_t));
		return value;
	}

	uint64_t reg_rip()
	{
		return reg_read<uint64_t>(UC_X86_REG_RIP);
	}

	uint64_t reg_rsp()
	{
		return reg_read<uint64_t>(UC_X86_REG_RSP);
	}

	void start(uint64_t start, uint64_t end = end_code)
	{
		uc_ctl_set_exits(uc, &end, 1);
		auto err = uc_emu_start(uc, start, 0, -1, -1);
		if (err != UC_ERR_OK)
		{
			puts("");
			printf("rip: 0x%llx, rsp: 0x%llx\n", reg_rip(), reg_rsp());
			throw std::runtime_error(std::string("uc_emu_start error: ") + uc_strerror(err));
		}
	}
};

static void emulate(uint64_t address, const std::vector<uint8_t>& code)
{
	Emulator emu;

	// Map wow64 code page
	auto wow64_code_address = 0x401000;
	std::vector<uint8_t> wow64_code(page_size, 0x90);
	wow64_code[1] = 0x48; // rex prefix in long mode, dec eax in compatibility mode
	wow64_code[ret_offset] = 0xC3;
	emu.mem_map(wow64_code_address, wow64_code.size(), UC_PROT_READ | UC_PROT_EXEC);
	emu.mem_write(wow64_code_address, wow64_code.data(), wow64_code.size());

	// Map wow64 stack page
	auto wow64_stack = 0x14F560;
	emu.mem_map(wow64_stack & ~0xFFFull, page_size, UC_PROT_READ | UC_PROT_WRITE);
	uint64_t testptr = wow64_code_address | 0x1234567800000000ull; // in theory the 0x12345678 is ignored
	emu.mem_write(wow64_stack, &testptr, sizeof(testptr));

	// Switch segment by executing iretq
	emu.push(windows_wow64_segment.ss); // SS
	emu.push(wow64_stack); // RSP
	emu.push(emu.reg_read<uint32_t>(UC_X86_REG_EFLAGS)); // EFLAGS
	emu.push(windows_wow64_segment.cs); // CS
	emu.push(wow64_code_address + ret_offset); // RIP
	emu.start(end_code + iretq_offset, wow64_code_address + 3);

	printf("rax: %016llx\n", emu.reg_read<uint64_t>(UC_X86_REG_RAX));

	return;

	constexpr uint64_t scratchsize = 0x1000;
	uint64_t scratchbase = 0;
	kernel_pool.start(&scratchbase, scratchsize, "scratch");
	printf("scratchbase: 0x%llx\n", scratchbase);
	emu.mem_protect(scratchbase, scratchsize);
	uint64_t nextaddr = scratchbase + 8;
	emu.mem_write(scratchbase + 0x68, &nextaddr, sizeof(nextaddr));
	emu.reg_write(UC_X86_REG_RCX, scratchbase);
	emu.reg_write(UC_X86_REG_RAX, 1ull);
	emu.mem_write(address, code.data(), code.size());
	auto rsp = emu.reg_rsp();
	uint64_t ret;
	emu.mem_read(rsp, &ret, sizeof(ret));
	printf("ret: 0x%llx\n", ret);
	emu.start(address);
}

int main(int argc, char** argv, char** envp)
{
	puts(kernel_pool.find_info(kernel_stack + 0x3210)->second.c_str());

	assert(kernel_pool.find_info(kernel_pool.pool_start() + 0x7000) == nullptr);

	uint64_t address = kernel_code;
	std::vector<uint8_t> code = {
0x84, 0xC0, 0x75, 0x35, 0x48, 0x8B, 0xCF, 0x4C, 0x8D, 0x41, 0x60, 0x48, 0x83, 0xC3, 0x10, 0x49,
0x8B, 0x00, 0x4C, 0x8B, 0x48, 0x08, 0x4D, 0x3B, 0xC8, 0x0F, 0x85, 0x67, 0xC0, 0x09, 0x00, 0x48,
0x89, 0x03, 0x4C, 0x89, 0x43, 0x08, 0x48, 0x89, 0x58, 0x08, 0x49, 0x89, 0x18, 0x48, 0x8B, 0x5C,
0x24, 0x40, 0x48, 0x83, 0xC4, 0x30, 0x5F, 0xC3, 0xCC, 0x48, 0xC1, 0xE0, 0x10, 0x48, 0x81, 0xE1,
0x00, 0x00, 0xFF, 0xFF, 0x48, 0x2B, 0xC8, 0x48, 0x81, 0xC1, 0x00, 0x00, 0x01, 0x00, 0xEB, 0xB7
	};
	code = { 0x48, 0x8B, 0xC3, 0xC3 };
	printf("code: %s\n", to_hex(code).c_str());
	printf("disassembled:\n%s\n", disassemble(address, code).c_str());
	try
	{
#if 0
		auto code = assemble(address, R"(
test al,al
jne fixme
mov rcx,rdi
back:
lea r8,qword ptr ds:[rcx+0x60]
add rbx,10
mov rax,qword ptr ds:[r8]
mov r9,qword ptr ds:[rax+8]
cmp r9,r8
jne ntdll.7FF84133AB61
mov qword ptr ds:[rbx],rax
mov qword ptr ds:[rbx+8],r8
mov qword ptr ds:[rax+8],rbx
mov qword ptr ds:[r8],rbx
mov rbx,qword ptr ss:[rsp+40]
add rsp,30
pop rdi
ret 
int3
fixme:
shl rax,10
and rcx,0xFFFFFFFFFFFF0000
sub rcx,rax
add rcx,0x10000
jmp back
)");
#endif
		emulate(address, code);
	}
	catch (const std::exception& x)
	{
		printf("Emulation exception: %s\n", x.what());
	}
}