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
static constexpr size_t kernel_code_size = page_size;
static constexpr uint64_t emulation_end_addr = 0x1337133713371337;

static uint64_t windows_tss_base;
static uint64_t windows_gdt_base;
static uint64_t kernel_stack;
static uint64_t kernel_code;
static uint64_t kernel_teb;

static DumbPoolAllocator kernel_pool(0xfffff8076d963000 - 0x963000, 0x964000);
static uint64_t kernel_range_size;
static uint64_t kernel_range_start = kernel_pool
.end(&windows_tss_base, page_size, "tss")
.end(&windows_gdt_base, page_size, "gdt")
.end(&kernel_stack, kernel_stack_size, "kernel stack")
.start(&kernel_code, kernel_code_size, "kernel code")
.pool_start(&kernel_range_size);

struct Emulator
{
	uc_engine* uc = nullptr;

	Emulator()
	{
		uc_assert(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
		init_kernel();
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

		// IDT (TODO)

		// Page for shellcode
		mem_protect(kernel_code, page_size, UC_PROT_READ | UC_PROT_EXEC);

		// Kernel stack
		mem_protect(kernel_stack, page_size, UC_PROT_NONE);
		reg_write(UC_X86_REG_RSP, kernel_stack + kernel_stack_size - 0x100);
		push(emulation_end_addr);
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

	void start(uint64_t start, uint64_t end = emulation_end_addr)
	{
		uc_assert(uc_emu_start(uc, start, end, -1, -1));
	}
};

static void emulate(uint64_t address, const std::vector<uint8_t>& code)
{
	Emulator emu;
	emu.mem_write(address, code.data(), code.size());
	emu.start(address);
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

int main(int argc, char** argv, char** envp)
{
	puts(kernel_pool.find_info(kernel_stack + 0x3210)->second.c_str());

	assert(kernel_pool.find_info(kernel_pool.pool_start() + 0x7000) == nullptr);

	uint64_t address = kernel_code;
	auto code = assemble(address, R"ASM(
mov rax, 0x10
mov rbx, rax
loop:
inc rbx
dec rax
jnz loop
xor rax, 0x1337
ret
)ASM");
	printf("code: %s\n", to_hex(code).c_str());
	printf("disassembled:\n%s\n", disassemble(address, code).c_str());
	try
	{
		emulate(address, code);
	}
	catch (const std::exception& x)
	{
		printf("Emulation exception: %s\n", x.what());
	}
}