// Copied from: https://www.unicorn-engine.org/docs/tutorial.html

#include <cstdlib>
#include <cstdint>
#include <vector>
#include <map>
#include <stdexcept>

#include <unicorn/unicorn.h>
#include <capstone/capstone.h>
#include <keystone/keystone.h>

// code to be emulated
#define X86_CODE32 "\x41\x4a" // INC ecx; DEC edx

// memory address where emulation starts
#define ADDRESS 0x1000000

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

	if(ks_option(ks, KS_OPT_SYM_RESOLVER, (size_t)sym_resolver) != KS_ERR_OK)
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

static int emulate(uint64_t address, const std::vector<uint8_t>& code)
{
	uc_engine* uc;
	uc_err err;
	int r_ecx = 0x1234;     // ECX register
	int r_edx = 0x7890;     // EDX register

	printf("Emulate i386 code\n");

	// Initialize emulator in X86-32bit mode
	err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
	if (err != UC_ERR_OK) {
		printf("Failed on uc_open() with error returned: %u\n", err);
		return -1;
	}

	// map 2MB memory for this emulation
	uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

	// write machine code to be emulated to memory
	if (uc_mem_write(uc, ADDRESS, X86_CODE32, sizeof(X86_CODE32) - 1)) {
		printf("Failed to write emulation code to memory, quit!\n");
		return -1;
	}

	// initialize machine registers
	uc_reg_write(uc, UC_X86_REG_ECX, &r_ecx);
	uc_reg_write(uc, UC_X86_REG_EDX, &r_edx);

	// emulate code in infinite time & unlimited instructions
	err = uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(X86_CODE32) - 1, 0, 0);
	if (err) {
		printf("Failed on uc_emu_start() with error returned %u: %s\n",
			err, uc_strerror(err));
	}

	// now print out some registers
	printf("Emulation done. Below is the CPU context\n");

	uc_reg_read(uc, UC_X86_REG_ECX, &r_ecx);
	uc_reg_read(uc, UC_X86_REG_EDX, &r_edx);
	printf(">>> ECX = 0x%x\n", r_ecx);
	printf(">>> EDX = 0x%x\n", r_edx);

	uc_close(uc);

	return r_ecx == 0x1235 && r_edx == 0x788f ? EXIT_SUCCESS : EXIT_FAILURE;
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
	uint64_t address = 0x10000;
	auto code = assemble(address, R"ASM(
mov rax, 0x10
mov rbx, rax
loop:
dec rax
inc rbx
jnz loop
xor rax, 0x1337
)ASM");
	printf("code: %s\n", to_hex(code).c_str());
	printf("disassembled:\n%s\n", disassemble(address, code).c_str());
}