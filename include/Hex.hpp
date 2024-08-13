#pragma once

#include "Types.hpp"

#include <iostream>
#include <string>
#include <vector>

namespace subst
{
	std::vector<u8> hex_str_to_bytes(std::string hex_string);

	template<typename T>
	void print_hex_vec(const std::vector<T>& vec)
	{
		for (T value : vec)
			std::cout << "0x" << std::hex << value << std::dec << '\n';
	}

	void print_bytes(const std::vector<u8>& bytes);
	void disasm_bytes(const std::vector<u8>& bytes, u64 starting_address, bool x86_32bit_mode);
}
