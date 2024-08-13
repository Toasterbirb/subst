#pragma once

#include "Types.hpp"

#include <capstone/capstone.h>
#include <span>

namespace subst
{
	class capstone
	{
	public:
		capstone(const std::span<const u8> bytes, const bool x86_mode, const size_t location, const size_t count = 0);
		~capstone();

		cs_insn* instructions;
		size_t instruction_count;

	private:
		csh handle;
	};
}
