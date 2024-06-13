#include "Hex.hpp"
#include "Mnemonics.hpp"
#include "Patch.hpp"
#include "Search.hpp"

#include <assert.h>
#include <capstone/capstone.h>
#include <cstdio>
#include <doctest/doctest.h>
#include <iostream>
#include <stdio.h>

namespace subst
{
	void patch_bytes(std::vector<u8>& bytes, const std::vector<subst_cmd>& commands, bool x86_32bit_mode)
	{
		constexpr u8 NOP = 0x90;

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

				case subst_cmd::mode::nopi:
				{
					// NOP out a mnemonic
					constexpr u8 disassembled_byte_count = 24;
					assert(bytes.size() >= disassembled_byte_count);
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
						// Patch out whatever the first mnemonic is at the given location
						std::cout << "patching out a " << insn[0].mnemonic << " instruction at 0x" << std::hex << cmd.location << '\n';

						for (u16 i = 0; i < insn[0].size; ++i)
							bytes[cmd.location + i] = NOP;

						cs_free(insn, instruction_count);
					}
					else
					{
						std::cout << "instruction to NOP could not be found\n";
					}

					cs_close(&handle);
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

	TEST_CASE("patch bytes")
	{
		SUBCASE("generic patching")
		{
			std::vector<u8> bytes = {
				0x7F, 0x45, 0x4C, 0x46,
				0x02, 0x01, 0x01, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x03, 0x00, 0x3E, 0x00,
				0x01, 0x00, 0x00, 0x00,
				0x90, 0x10, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00
			};

			const u32 original_bytes_count = bytes.size();

			std::vector<std::string> subst = {
				"rep ; 7F 45 4C 46 ; 00 00 00 00",
				"nop ; 0x4 ; 4",
				"repat ; 0x8 ; 12 34 56 78",
				"nop ; 03 00 3E 00"
			};

			std::vector<subst_cmd> commands = subst::parse_subst(subst);
			patch_bytes(bytes, commands, false);

			const std::vector<u8> patched_bytes = {
				0x00, 0x00, 0x00, 0x00,
				0x90, 0x90, 0x90, 0x90,
				0x12, 0x34, 0x56, 0x78,
				0x00, 0x00, 0x00, 0x00,
				0x90, 0x90, 0x90, 0x90,
				0x01, 0x00, 0x00, 0x00,
				0x90, 0x10, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00
			};

			CHECK(bytes == patched_bytes);
		}

		SUBCASE("patch out a function call")
		{
			std::vector<u8> bytes = {
				0x48, 0x89, 0xc7,
				0xe8, 0x6b, 0xfe, 0xff, 0xff, // This line should get patched out with NOP
				0x48, 0x89, 0x45, 0xf8,
				0x48, 0x8d, 0x05, 0x3d, 0x0c, 0x00,
				0x48, 0x89, 0x45, 0xf0,
				0x48, 0x8b, 0x45, 0xc0,
			};

			const u32 original_bytes_count = bytes.size();

			std::vector<std::string> subst = {
				"nopi ; 0x3"
			};

			std::vector<subst_cmd> commands = subst::parse_subst(subst);
			patch_bytes(bytes, commands, false);

			const std::vector<u8> patched_bytes = {
				0x48, 0x89, 0xc7,
				0x90, 0x90, 0x90, 0x90, 0x90,
				0x48, 0x89, 0x45, 0xf8,
				0x48, 0x8d, 0x05, 0x3d, 0x0c, 0x00,
				0x48, 0x89, 0x45, 0xf0,
				0x48, 0x8b, 0x45, 0xc0,
			};

			CHECK(bytes == patched_bytes);
		}
	}
}
