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
		{ mnemonic_str::je, mnemonic::je },
		{ mnemonic_str::jne, mnemonic::jne },
		{ mnemonic_str::jz, mnemonic::jz },
		{ mnemonic_str::jnz, mnemonic::jnz },
		{ mnemonic_str::jle, mnemonic::jle },
		{ mnemonic_str::jge, mnemonic::jge },
		{ mnemonic_str::jg, mnemonic::jg },
		{ mnemonic_str::jl, mnemonic::jl },
	};
}
