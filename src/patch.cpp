#include "Hex.hpp"
#include "Mnemonics.hpp"
#include "Patch.hpp"
#include "Search.hpp"

#include <assert.h>
#include <capstone/capstone.h>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <regex>
#include <sstream>
#include <stdio.h>

namespace subst
{
	////////////////////////////////////
	// Private functions declarations //
	////////////////////////////////////

	std::vector<std::string> tokenize_string(const std::string& line, const char separator);



	std::vector<std::string> tokenize_string(const std::string& line, const char separator)
	{
		std::vector<std::string> tokens;

		std::istringstream line_stream(line);
		std::string token;

		while (std::getline(line_stream, token, separator))
			tokens.push_back(token);

		return tokens;
	}

	std::vector<subst_cmd> parse_subst_file(const std::string& subst_file_path)
	{
		std::ifstream file(subst_file_path);

		std::vector<subst_cmd> commands;
		std::string line;

		// Read the subst file in line by line (ignoring empty lines and comments)
		while (std::getline(file, line))
		{
			const std::string original_line = line;

			// Remove all whitespace
			std::erase(line, ' ');

			// Remove comments
			std::regex comment_pattern("#.*");
			line = std::regex_replace(line, comment_pattern, "");

			// Ignore empty lines
			if (line.empty())
				continue;

			// Remove all instances of "0x" from the line, since the location
			// might be written in the following format 0x00112 etc. which doesn't work with std::stoi
			std::regex zero_x_pattern("0x");
			line = std::regex_replace(line, zero_x_pattern, "");

			// Split the line into tokens
			constexpr char split_char = ';';
			std::vector<std::string> tokens = tokenize_string(line, split_char);


			if (tokens.size() <= 1)
			{
				std::cout << "invalid line: " << original_line << '\n';
				exit(1);
			}

			// Parse the tokens
			subst_cmd cmd;
			cmd.mode = subst_cmd::str_to_mode.at(tokens[0]);

			switch (cmd.mode)
			{
				// rep ; bytes ; replacement_bytes
				case subst_cmd::mode::rep:
				{
					if (tokens.size() != 3)
					{
						std::cout << "invalid byte replacement: " << original_line << '\n';
						exit(1);
					}

					cmd.bytes = hex_str_to_bytes(tokens[1]);
					cmd.replacement_bytes = hex_str_to_bytes(tokens[2]);
					break;
				}

				// repat ; location ; replacement_bytes
				case subst_cmd::mode::repat:
				{
					if (tokens.size() != 3)
					{
						std::cout << "invalid location replacement: " << original_line << '\n';
						exit(1);
					}

					cmd.location = std::stoi(tokens[1], 0, 16);
					cmd.replacement_bytes = hex_str_to_bytes(tokens[2]);

					break;
				}

				case subst_cmd::mode::nop:
				{
					// nop ; bytes
					if (tokens.size() == 2)
					{
						cmd.bytes = hex_str_to_bytes(tokens[1]);
					}
					// nop ; location ; amount_of_bytes_to_replace
					else if (tokens.size() == 3)
					{
						cmd.location = std::stoi(tokens[1], 0, 16);
						cmd.count = std::stoi(tokens[2]);
					}
					else
					{
						std::cout << "invalid NOP replacement: " << original_line << '\n';
						exit(1);
					}

					break;
				}

				// inv ; location
				case subst_cmd::mode::inv:
				{
					if (tokens.size() != 2)
					{
						std::cout << "invalid conditional inversion: " << original_line << '\n';
						exit(1);
					}

					cmd.location = std::stoi(tokens[1], 0, 16);

					break;
				}
			}

			commands.push_back(cmd);
		}

		return commands;
	}

	void patch_bytes(std::vector<u8>& bytes, const std::vector<subst_cmd>& commands, bool x86_32bit_mode)
	{
		for (const subst_cmd& cmd : commands)
		{
			switch (cmd.mode)
			{
				case subst_cmd::mode::rep:
				{
					if (cmd.bytes.size() != cmd.replacement_bytes.size())
					{
						std::cout << "the amount of bytes to replace doesn't match with the amount of replacement bytes\n";
						exit(1);
					}

					std::cout << "replacing all instances of ";
					print_bytes(cmd.bytes);
					std::cout << "with ";
					print_bytes(cmd.replacement_bytes);

					std::cout << '\n';

					// Find all locations where the byte array appears at
					std::vector<size_t> locations = subst::search_bytes(bytes, cmd.bytes);

					for (size_t location : locations)
					{
						std::cout << " -> 0x" << std::hex << location << '\n';
						for (size_t i = 0; i < cmd.bytes.size(); ++i)
							bytes[location + i] = cmd.replacement_bytes[i];
					}

					break;
				}

				case subst_cmd::mode::repat:
				{
					std::cout << "replacing " << cmd.replacement_bytes.size() << " bytes at 0x" << std::hex << cmd.location << '\n';

					// Replace bytes starting from the given point
					for (u64 i = cmd.location; i < cmd.location + cmd.replacement_bytes.size() && i < bytes.size(); ++i)
						bytes.at(i) = cmd.replacement_bytes.at(i - cmd.location);

					break;
				}

				case subst_cmd::mode::nop:
				{
					constexpr u8 NOP = 0x90;

					// If count is not set, replace all instances of the byte array in
					// the file with NOPs
					if (cmd.count == 0)
					{
						assert(!cmd.bytes.empty());

						std::cout << "replacing all instances of ";
						print_bytes(cmd.bytes);
						std::cout << "with NOPs\n";

						// Find all locations where the byte array appears at
						std::vector<size_t> locations = subst::search_bytes(bytes, cmd.bytes);

						for (size_t location : locations)
						{
							std::cout << " -> 0x" << std::hex << location << '\n';
							for (size_t i = 0; i < cmd.bytes.size(); ++i)
								bytes[location + i] = NOP;
						}
					}
					else
					{
						// NOP out the given amount of bytes starting from the given location
						std::cout << "replacing " << cmd.count << " bytes with NOP at 0x" << std::hex << cmd.location << '\n';

						for (size_t i = cmd.location; i < cmd.location + cmd.count && i < bytes.size(); ++i)
							bytes[i] = NOP;
					}

					break;
				}

				case subst_cmd::mode::inv:
				{
					// Disassemble some bytes starting from the given location to figure out
					// how to invert the conditional (if there even is one)
					constexpr u8 disassembled_byte_count = 24;
					std::span<u8> bytes_to_disassemble(bytes.begin() + cmd.location, bytes.begin() + cmd.location + disassembled_byte_count);

					csh handle;
					cs_insn* insn;

					cs_mode capstone_mode = CS_MODE_64;
					if (x86_32bit_mode)
						capstone_mode = CS_MODE_32;

					if (cs_open(CS_ARCH_X86, capstone_mode, &handle) != CS_ERR_OK)
					{
						std::cout << "couldn't initialize capstone\n";
						return;
					}

					size_t instruction_count = cs_disasm(handle, bytes_to_disassemble.data(), bytes_to_disassemble.size(), cmd.location, 0, &insn);
					if (instruction_count > 0)
					{
						// Only check the first instruction since that is supposed to be a conditional
						mnemonic conditional;

						try
						{
							conditional = str_to_mnemonic.at(insn[0].mnemonic);
						}
						catch (std::exception e)
						{
							std::cout << "error! unimplemented conditional inversion: " << insn[0].mnemonic << '\n';
							exit(5);
						}


						const auto log_invert = [cmd](const std::string& left_operand, const std::string& right_operand)
						{
							std::cout << "inverting " << left_operand << " -> " << right_operand << " at " << std::hex << "0x" << cmd.location << '\n';
						};

						constexpr u8 is_equal = 0x75;
						constexpr u8 not_equal = 0x74;
						constexpr u8 less_than_or_equal = 0x7e;
						constexpr u8 greater_than_or_equal = 0x7d;
						constexpr u8 less_than = 0x7c;
						constexpr u8 greater_than = 0x7f;

						switch (conditional)
						{
							case mnemonic::je:
								log_invert(mnemonic_str::je, mnemonic_str::jne);
								bytes[cmd.location] = is_equal;
								break;

							case mnemonic::jne:
								log_invert(mnemonic_str::jne, mnemonic_str::je);
								bytes[cmd.location] = not_equal;
								break;

							case mnemonic::jz:
								log_invert(mnemonic_str::jz, mnemonic_str::jnz);
								bytes[cmd.location] = is_equal;
								break;

							case mnemonic::jnz:
								log_invert(mnemonic_str::jnz, mnemonic_str::jz);
								bytes[cmd.location] = not_equal;
								break;

							case mnemonic::jle:
								log_invert(mnemonic_str::jle, mnemonic_str::jge);
								bytes[cmd.location] = greater_than_or_equal;
								break;

							case mnemonic::jge:
								log_invert(mnemonic_str::jge, mnemonic_str::jle);
								bytes[cmd.location] = less_than_or_equal;
								break;

							case mnemonic::jl:
								log_invert(mnemonic_str::jl, mnemonic_str::jg);
								bytes[cmd.location] = greater_than;
								break;

							case mnemonic::jg:
								log_invert(mnemonic_str::jg, mnemonic_str::jl);
								bytes[cmd.location] = less_than;
								break;
						}

						cs_free(insn, instruction_count);
					}
					else
					{
						std::cout << "no conditional instrunctions were found at location " << std::hex << cmd.location << '\n';
					}

					cs_close(&handle);

					break;
				}
			}
		}
	}
}
