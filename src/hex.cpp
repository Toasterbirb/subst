#include "Capstone.hpp"
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
		const std::regex zero_x_pattern("0x");
		hex_string = std::regex_replace(hex_string, zero_x_pattern, "");

		while (!hex_string.empty())
		{
			try
			{
				const u8 byte = hex_string.size() != 1
					? std::stoi(hex_string.substr(0, 2), 0, 16)
					: std::stoi(hex_string.substr(0, 1), 0, 16);

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
		const capstone capstone(bytes, x86_32bit_mode, starting_address);

		if (capstone.instruction_count > 0)
		{
			constexpr u8 bytes_per_instruction = 24;

			for (size_t i = 0; i < capstone.instruction_count; ++i)
			{
				std::cout << std::left << "0x" << capstone.instructions[i].address << ":\t" << std::setw(12) << capstone.instructions[i].mnemonic << std::setw(32) << capstone.instructions[i].op_str;

				// Print the bytes
				for (u8 j = 0; j < capstone.instructions[i].size; ++j)
					printf("%02x ", capstone.instructions[i].bytes[j]);

				std::cout << "\n";
			}
		}
		else
		{
			std::cout << "No instructions could be disassembled from the hex string\n";
		}
	}
}
