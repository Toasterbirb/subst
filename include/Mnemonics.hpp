#pragma once

#include <string>
#include <unordered_map>

namespace subst
{
	enum class mnemonic
	{
		je, jne, jz, jnz, jle, jge, jg, jl
	};

	namespace mnemonic_str
	{
		static inline const std::string je = "je";
		static inline const std::string jne = "jne";
		static inline const std::string jz = "jz";
		static inline const std::string jnz = "jnz";
		static inline const std::string jle = "jle";
		static inline const std::string jge = "jge";
		static inline const std::string jg = "jg";
		static inline const std::string jl = "jl";
	}

	static const std::unordered_map<std::string, mnemonic> str_to_mnemonic = {
		{ "je", mnemonic::je },
		{ "jne", mnemonic::jne },
		{ "jz", mnemonic::jz },
		{ "jnz", mnemonic::jnz },
		{ "jle", mnemonic::jle },
		{ "jge", mnemonic::jge },
		{ "jg", mnemonic::jg },
		{ "jl", mnemonic::jl },
	};
}
