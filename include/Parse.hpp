#pragma once

#include "Types.hpp"

#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace subst
{
	struct subst_cmd
	{
		enum class mode
		{
			rep, repat, nop, nopi, inv, jmp
		};

		// string to mode mappings
		static inline const std::unordered_map<std::string, mode> str_to_mode = {
			{ "rep", mode::rep },
			{ "repat", mode::repat },
			{ "nop", mode::nop },
			{ "nopi", mode::nopi },
			{ "inv", mode::inv},
			{ "jmp", mode::jmp },
		};

		mode mode;

		std::optional<std::vector<u8>> bytes;
		std::optional<std::vector<u8>> replacement_bytes;
		u64 location{};
		u64 destination{};
		u64 count{};
	};

	std::vector<std::string> read_file(const std::string& file_path);
	std::vector<subst_cmd> parse_subst(const std::vector<std::string>& subst_lines);
	subst_cmd parse_subst_tokens(const std::vector<std::string>& tokens, const std::string& original_line = "<nothing>");
}
