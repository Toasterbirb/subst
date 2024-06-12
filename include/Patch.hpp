#pragma once

#include "Types.hpp"

#include <string>
#include <unordered_map>
#include <vector>

namespace subst
{
	struct subst_cmd
	{
		enum class mode
		{
			rep, repat, nop, inv
		};

		// string to mode mappings
		static inline const std::unordered_map<std::string, mode> str_to_mode = {
			{ "rep", mode::rep },
			{ "repat", mode::repat },
			{ "nop", mode::nop },
			{ "inv", mode::inv},
		};

		mode mode;

		std::vector<u8> bytes;
		std::vector<u8> replacement_bytes;
		u64 location{};
		u64 count{};
	};

	std::vector<subst_cmd> parse_subst_file(const std::string& subst_file_path);
	void patch_bytes(std::vector<u8>& bytes, const std::vector<subst_cmd>& commands, bool x86_32bit_mode);
}
