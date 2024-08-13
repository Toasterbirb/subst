#include "Capstone.hpp"

#include <iostream>

namespace subst
{
	capstone::capstone(const std::span<const u8> bytes, const bool x86_mode, const size_t location, const size_t count)
	{
		const cs_mode mode = x86_mode ? CS_MODE_32 : CS_MODE_64;

		if (cs_open(CS_ARCH_X86, mode, &handle) != CS_ERR_OK)
		{
			std::cout << "couldn't initialize capstone\n";
			return;
		}

		instruction_count = cs_disasm(handle, bytes.data(), bytes.size(), location, count, &instructions);
	}

	capstone::~capstone()
	{
		if (instruction_count > 0)
			cs_free(instructions, instruction_count);

		cs_close(&handle);
	}
}
