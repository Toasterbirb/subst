#include "Hex.hpp"

#include <capstone/capstone.h>
#include <cstdlib>
#include <doctest/doctest.h>
#include <iomanip>
#include <iostream>
#include <regex>

namespace subst
{
	std::vector<u8> hex_str_to_bytes(std::string hex_string)
	{
		std::vector<u8> hex_values;

		// Remove all whitespace from the hex string
		std::erase(hex_string, ' ');

		// Remove all instances of "0x" from the string
		std::regex zero_x_pattern("0x");
		hex_string = std::regex_replace(hex_string, zero_x_pattern, "");

		while (!hex_string.empty())
		{
			try
			{
				u8 byte = 0;

				if (hex_string.size() != 1)
					byte = std::stoi(hex_string.substr(0, 2), 0, 16);
				else
					byte = std::stoi(hex_string.substr(0, 1), 0, 16);

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

	TEST_CASE("hex_str_to_bytes")
	{
		CHECK(hex_str_to_bytes("0") == std::vector<u8>{ 0x0 });
		CHECK(hex_str_to_bytes("1") == std::vector<u8>{ 0x1 });
		CHECK(hex_str_to_bytes("7f45") == std::vector<u8>{ 0x7f, 0x45 });
		CHECK(hex_str_to_bytes("7f45 4c46") == std::vector<u8> { 0x7f, 0x45, 0x4c, 0x46 });
		CHECK(hex_str_to_bytes("7f 45 4c 46") == std::vector<u8>{ 0x7f, 0x45, 0x4c, 0x46 });
		CHECK(hex_str_to_bytes("7f454c46") == std::vector<u8>{ 0x7f, 0x45, 0x4c, 0x46 });
		CHECK(hex_str_to_bytes("7f454c46020101030000000000000000") == std::vector<u8>{ 0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x03,
		                                                                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
		CHECK(hex_str_to_bytes("0x7f 0x45 0x4c 0x46") == std::vector<u8>{ 0x7f, 0x45, 0x4c, 0x46 });
		CHECK(hex_str_to_bytes("0x7f0x450x4c0x46") == std::vector<u8>{ 0x7f, 0x45, 0x4c, 0x46 });
	}

	void print_bytes(const std::vector<u8>& bytes)
	{
		for (size_t i = 0; i < bytes.size(); ++i)
			printf("%02x ", bytes[i]);
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
					printf("%02x ", insn[i].bytes[j]);

				std::cout << "\n";
			}

			cs_free(insn, instruction_count);
		}
		else
		{
			std::cout << "No instructions could be disassembled from the hex string\n";
		}

		cs_close(&handle);
	}
}
