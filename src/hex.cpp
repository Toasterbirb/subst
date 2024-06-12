#include "Hex.hpp"

#include <capstone/capstone.h>
#include <cstdlib>
#include <iomanip>
#include <iostream>

std::vector<u8> hex_str_to_int(std::string hex_string)
{
	std::vector<u8> hex_values;

	while (!hex_string.empty())
	{
		// Remove any whitespace if there's some at the beginning
		size_t first_non_whitespace_char = hex_string.find_first_not_of(' ');
		if (first_non_whitespace_char != std::string::npos)
			hex_string = hex_string.erase(0, first_non_whitespace_char);

		try
		{
			u8 byte = std::stoi(hex_string.substr(0, 2), 0, 16);
			hex_values.emplace_back(byte);
		}
		catch (std::exception e)
		{
			std::cout << "Error processing hex value: " << hex_string.substr(0, 2) << "\n";
			exit(2);
		}

		// Clear the first processed byte
		hex_string = hex_string.erase(0, 2);
	}

	return hex_values;
}

void disasm_bytes(const std::vector<u8>& bytes, u64 starting_address, bool x86_32bit_mode)
{
	csh handle;
	cs_insn* insn;

	cs_mode capstone_mode = CS_MODE_64;
	if (x86_32bit_mode)
		capstone_mode = CS_MODE_32;

	if (cs_open(CS_ARCH_X86, capstone_mode, &handle) != CS_ERR_OK)
	{
		std::cout << "Couldn't initialize capstone\n";
		return;
	}

	size_t instruction_count = cs_disasm(handle, bytes.data(), bytes.size(), 0x0, 0, &insn);
	if (instruction_count > 0)
	{
		constexpr u8 bytes_per_instruction = 24;

		for (size_t i = 0; i < instruction_count; ++i)
		{
			std::cout << std::left << "0x" << insn[i].address << ":\t" << std::setw(12) << insn[i].mnemonic << std::setw(32) << insn[i].op_str;

			// Print the bytes
			for (u8 j = 0; j < insn[i].size; ++j)
				std::cout << std::hex << (u32)insn[i].bytes[j] << " ";

			std::cout << "\n";
		}
	}
	else
	{
		std::cout << "No instructions could be disassembled from the hex string\n";
	}
}
