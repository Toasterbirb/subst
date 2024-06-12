#pragma once

#include "Parse.hpp"
#include "Types.hpp"

#include <vector>

namespace subst
{
	void patch_bytes(std::vector<u8>& bytes, const std::vector<subst_cmd>& commands, bool x86_32bit_mode);
}
