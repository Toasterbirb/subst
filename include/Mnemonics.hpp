#pragma once

#include <string>
#include <unordered_map>

namespace subst
{
	enum class mnemonic
	{
		je, jne, jz, jnz
	};

	namespace mnemonic_str
	{
		static inline const std::string je = "je";
		static inline const std::string jne = "jne";
		static inline const std::string jz = "jz";
		static inline const std::string jnz = "jnz";
	}

	static const std::unordered_map<std::string, mnemonic> str_to_mnemonic = {
		{ "je", mnemonic::je },
		{ "jne", mnemonic::jne },
		{ "jz", mnemonic::jz },
		{ "jnz", mnemonic::jnz }
	};
}
