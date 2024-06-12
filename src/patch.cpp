#include "Hex.hpp"
#include "Search.hpp"
#include "Patch.hpp"

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
			std::vector<std::string> tokens;

			{
				std::istringstream line_stream(line);
				std::string token;

				while (std::getline(line_stream, token, split_char))
					tokens.push_back(token);
			}

			if (tokens.size() <= 1)
			{
				std::cout << "Invalid line: " << original_line << '\n';
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
						std::cout << "Invalid byte replacement: " << original_line << '\n';
						exit(1);
					}

					cmd.bytes = hex_str_to_int(tokens[1]);
					cmd.replacement_bytes = hex_str_to_int(tokens[2]);
					break;
				}

				// repat ; location ; replacement_bytes
				case subst_cmd::mode::repat:
				{
					if (tokens.size() != 3)
					{
						std::cout << "Invalid location replacement: " << original_line << '\n';
						exit(1);
					}

					cmd.location = std::stoi(tokens[1], 0, 16);
					cmd.replacement_bytes = hex_str_to_int(tokens[2]);

					break;
				}

				case subst_cmd::mode::nop:
				{
					// nop ; bytes
					if (tokens.size() == 2)
					{
						cmd.bytes = hex_str_to_int(tokens[1]);
					}
					// nop ; location ; amount_of_bytes_to_replace
					else if (tokens.size() == 3)
					{
						cmd.location = std::stoi(tokens[1], 0, 16);
						cmd.count = std::stoi(tokens[2]);
					}
					else
					{
						std::cout << "Invalid NOP replacement: " << original_line << '\n';
						exit(1);
					}

					break;
				}

				// inv ; location
				case subst_cmd::mode::inv:
				{
					if (tokens.size() != 2)
					{
						std::cout << "Invalid conditional inversion: " << original_line << '\n';
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
						std::cout << "The amount of bytes to replace doesn't match with the amount of replacement bytes\n";
						exit(1);
					}

					std::cout << "replacing all instances of ";
					for (size_t i = 0; i < cmd.bytes.size(); ++i)
						printf("%02x ", cmd.bytes[i]);

					std::cout << "with ";

					for (size_t i = 0; i < cmd.bytes.size(); ++i)
						printf("%02x ", cmd.replacement_bytes[i]);

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
						for (size_t i = 0; i < cmd.bytes.size(); ++i)
							printf("%02x ", cmd.bytes[i]);
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
						enum class mnemonic
						{
							je, jne, jz, jnz
						};

						static const std::unordered_map<std::string, mnemonic> str_to_mnemonic = {
							{ "je", mnemonic::je },
							{ "jne", mnemonic::jne },
							{ "jz", mnemonic::jz },
							{ "jnz", mnemonic::jnz }
						};

						// Only check the first instruction since that is supposed to be a conditional
						mnemonic conditional = str_to_mnemonic.at(insn[0].mnemonic);

						auto log_invert = [cmd](const std::string& left_operand, const std::string& right_operand)
						{
							std::cout << "inverting " << left_operand << " -> " << right_operand << " at " << std::hex << "0x" << cmd.location << '\n';
						};

						switch (conditional)
						{
							case mnemonic::je:
								log_invert("je", "jne");
								bytes[cmd.location] = 0x75;
								break;

							case mnemonic::jne:
								log_invert("jne", "je");
								bytes[cmd.location] = 0x74;
								break;

							case mnemonic::jz:
								log_invert("jz", "jnz");
								bytes[cmd.location] = 0x75;
								break;

							case mnemonic::jnz:
								log_invert("jnz", "jz");
								bytes[cmd.location] = 0x74;
								break;

							default:
								std::cout << "unhandled conditional inverstion: " << insn[0].mnemonic << '\n';
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
