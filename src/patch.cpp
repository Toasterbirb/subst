#include "Capstone.hpp"
#include "Hex.hpp"
#include "Mnemonics.hpp"
#include "Patch.hpp"
#include "Search.hpp"

#include <assert.h>
#include <capstone/capstone.h>
#include <cstdio>
#include <cstdlib>
#include <doctest/doctest.h>
#include <iostream>
#include <stdio.h>

namespace subst
{
	void patch_bytes(std::vector<u8>& bytes, const std::vector<subst_cmd>& commands, const bool x86_32bit_mode)
	{
		constexpr u8 NOP = 0x90;

		for (const subst_cmd& cmd : commands)
		{
			switch (cmd.mode)
			{
				case subst_cmd::mode::rep:
				{
					assert(cmd.bytes.has_value());
					assert(cmd.replacement_bytes.has_value());

					if (cmd.bytes.value().size() != cmd.replacement_bytes.value().size())
					{
						std::cout << "the amount of bytes to replace doesn't match with the amount of replacement bytes\n";
						exit(1);
					}

					std::cout << "replacing all instances of " << byte_str(cmd.bytes.value()) << " with " << byte_str(cmd.replacement_bytes.value()) << '\n';

					// Find all locations where the byte array appears at
					const std::vector<size_t> locations = subst::search_bytes(bytes, cmd.bytes.value());

					for (size_t location : locations)
					{
						std::cout << " -> 0x" << std::hex << location << '\n';
						for (size_t i = 0; i < cmd.bytes.value().size(); ++i)
							bytes[location + i] = cmd.replacement_bytes.value()[i];
					}

					break;
				}

				case subst_cmd::mode::repat:
				{
					assert(cmd.replacement_bytes.has_value());

					std::cout << "replacing " << std::dec << cmd.replacement_bytes.value().size() << " bytes at 0x" << std::hex << cmd.location << '\n';

					// Replace bytes starting from the given point
					for (u64 i = cmd.location; i < cmd.location + cmd.replacement_bytes.value().size() && i < bytes.size(); ++i)
						bytes.at(i) = cmd.replacement_bytes.value().at(i - cmd.location);

					break;
				}

				case subst_cmd::mode::nop:
				{
					// If count is not set, replace all instances of the byte array in
					// the file with NOPs
					if (cmd.count == 0)
					{
						assert(cmd.bytes.has_value());

						std::cout << "replacing all instances of " << byte_str(cmd.bytes.value()) << " with NOPs\n";

						// Find all locations where the byte array appears at
						const std::vector<size_t> locations = subst::search_bytes(bytes, cmd.bytes.value());

						for (size_t location : locations)
						{
							std::cout << " -> 0x" << std::hex << location << '\n';
							for (size_t i = 0; i < cmd.bytes.value().size(); ++i)
								bytes[location + i] = NOP;
						}
					}
					else
					{
						// NOP out the given amount of bytes starting from the given location
						std::cout << "replacing " << std::dec << cmd.count << " bytes with NOP at 0x" << std::hex << cmd.location << '\n';

						if (cmd.location + cmd.count > bytes.size())
							std::cout << "note: the amount of bytes to nop would be enough to go outside of the binary\n"
								<< "only " << std::dec << bytes.size() - cmd.location << " bytes will be actually replaced with nops\n";

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

					if (cmd.location > bytes.size())
					{
						std::cout << "error in a nopi command!\n"
							<< "location 0x" << std::hex << cmd.location << " is out of bounds\n"
							<< "the size of the program is " << std::dec << bytes.size() << " bytes\n";
						exit(1);
					}

					const std::span<u8> bytes_to_disassemble(bytes.begin() + cmd.location, bytes.begin() + cmd.location + disassembled_byte_count);

					const capstone capstone(bytes_to_disassemble, x86_32bit_mode, cmd.location);

					if (capstone.instruction_count > 0)
					{
						// Patch out whatever the first instruction is at the given location
						// (or multiple instructions starting from the location if the count > 1)

						u64 location_offset = 0;
						for (u64 i = 0; i < cmd.count; ++i)
						{
							// prevent buffer overflows
							if (cmd.location + capstone.instructions[i].size > bytes.size())
							{
								std::cout << "error in a nopi command!\n"
									<< "the amount of instructions to nop (" << std::dec << cmd.count << ") from 0x" << std::hex << cmd.location << " onwards\n"
									<< "reaches outside of the binary\n";
								exit(1);
							}

							std::cout << "patching out a " << capstone.instructions[i].mnemonic << " instruction at 0x" << std::hex << cmd.location + location_offset << '\n';
							for (u16 j = 0; j < capstone.instructions[i].size; ++j)
								bytes[cmd.location + j + location_offset] = NOP;

							location_offset += capstone.instructions[i].size;
						}
					}
					else
					{
						std::cout << "instruction to NOP could not be found\n";
					}

					break;
				}

				case subst_cmd::mode::inv:
				{
					// Disassemble some bytes starting from the given location to figure out
					// how to invert the conditional (if there even is one)
					constexpr u8 disassembled_byte_count = 24;
					const std::span<u8> bytes_to_disassemble(bytes.begin() + cmd.location, bytes.begin() + cmd.location + disassembled_byte_count);

					const capstone capstone(bytes_to_disassemble, x86_32bit_mode, cmd.location);

					if (capstone.instruction_count > 0)
					{
						// Only check the first instruction since that is supposed to be a conditional
						mnemonic conditional;

						try
						{
							conditional = str_to_mnemonic.at(capstone.instructions[0].mnemonic);
						}
						catch (std::exception e)
						{
							std::cout << "error! unimplemented conditional inversion: " << capstone.instructions[0].mnemonic << '\n';
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
					}
					else
					{
						std::cout << "no conditional instrunctions were found at location " << std::hex << cmd.location << '\n';
					}

					break;
				}

				case subst_cmd::mode::jmp:
				{
					// Calculate the jumping distance
					// If the distance is more than -128 or less than 128, we can do a "short jump" with 8-bit offset
					// If the distance is longer, we'll do a "near jump" with a 32-bit offset

					const i64 distance = static_cast<i64>(cmd.destination) - static_cast<i64>(cmd.location);

					if (distance - 30 <= 128)
					{
						std::cout << "creating a short jump 0x" << std::hex << cmd.location  << " -> 0x" << cmd.destination << std::dec << " (" << std::dec << distance << " bytes)\n";

						// Do a short jump
						bytes[cmd.location] = 0xeb;
						bytes[cmd.location + 1] = distance - 2;
					}
					else
					{
						std::cout << "creating a near jump 0x" << std::hex << cmd.location  << " -> 0x" << cmd.destination << std::dec << " (" << std::dec << distance << " bytes)\n";

						// Do a near jump
						bytes[cmd.location] = 0xe9;

						const i32 offset_distance = distance - 5;
						bytes[cmd.location + 1] = (offset_distance & 0x000000ffUL);
						bytes[cmd.location + 2] = (offset_distance & 0x0000ff00UL) >> 8;
						bytes[cmd.location + 3] = (offset_distance & 0x00ff0000UL) >> 16;
						bytes[cmd.location + 4] = (offset_distance & 0xff000000UL) >> 24;
					}

					if (cmd.location + distance > bytes.size())
						std::cout << "warning: the created jump jumps to a location outside the bounds of the binary\n";

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

		SUBCASE("patch out multiple instructions at once")
		{
			std::vector<u8> bytes = {
				0x48, 0x89, 0xc7,
				0xe8, 0x6b, 0xfe, 0xff, 0xff, // This line should get patched out with NOP
				0x48, 0x89, 0x45, 0xf8, // This line should get patched out with NOP
				0x48, 0x8d, 0x05, 0x3d, 0x0c, 0x00,
				0x48, 0x89, 0x45, 0xf0,
				0x48, 0x8b, 0x45, 0xc0,
			};

			const u32 original_bytes_count = bytes.size();

			std::vector<std::string> subst = {
				"nopi ; 0x3 ; 2"
			};

			std::vector<subst_cmd> commands = subst::parse_subst(subst);
			patch_bytes(bytes, commands, false);

			const std::vector<u8> patched_bytes = {
				0x48, 0x89, 0xc7,
				0x90, 0x90, 0x90, 0x90, 0x90,
				0x90, 0x90, 0x90, 0x90,
				0x48, 0x8d, 0x05, 0x3d, 0x0c, 0x00,
				0x48, 0x89, 0x45, 0xf0,
				0x48, 0x8b, 0x45, 0xc0,
			};

			CHECK(bytes == patched_bytes);

		}

		SUBCASE("create a short jmp instruction")
		{
			std::vector<u8> bytes = {
				0xe8, 0x04, 0xfc, 0xff, 0xff,
				0xb8, 0x01, 0x00, 0x00, 0x00,
				0x90, 0x90, // Jump from here
				0x48, 0x8d, 0x3d, 0xe2, 0x0b, 0x00, 0x00,
				0xe8, 0xf1, 0xfb, 0xff, 0xff,
				0x48, 0x8d, 0x05, 0xeb, 0x0b, 0x00, 0x00,
				0x48, 0x89, 0x45, 0xd8,
				0x48, 0x8b, 0x45, 0xc0,
				0x48, 0x83, 0xc0, 0x08,
				0x48, 0x8b, 0x10,
				0x48, 0x8b, 0x45, 0xd8,
				0x48, 0x89, 0xd6,
				0x48, 0x89, 0xc7,
				0xe8, 0x29, 0xfe, 0xff, 0xff,
				0x48, 0x89, 0x45, 0xd0,
				0x48, 0x8b, 0x45, 0xd0,
				0x48, 0x89, 0xc6,
				0x48, 0x8d, 0x3d, 0xd1, 0x0b, 0x00, 0x00,
				0xb8, 0x00, 0x00, 0x00, 0x00,
				0xe8, 0xd0, 0xfb, 0xff, 0xff,
				0xb8, 0x00, 0x00, 0x00, 0x00,
				0xc9, // To here
				0xc3,
			};

			const u32 original_bytes_count = bytes.size();

			std::vector<std::string> subst = {
				"jmp ; 0xa ; 0x5e"
			};

			std::vector<subst_cmd> commands = subst::parse_subst(subst);
			patch_bytes(bytes, commands, false);

			CHECK(bytes.size() == original_bytes_count);

			const std::vector<u8> patched_bytes = {
				0xe8, 0x04, 0xfc, 0xff, 0xff,
				0xb8, 0x01, 0x00, 0x00, 0x00,
				0xeb, 0x52, // Jump from here
				0x48, 0x8d, 0x3d, 0xe2, 0x0b, 0x00, 0x00,
				0xe8, 0xf1, 0xfb, 0xff, 0xff,
				0x48, 0x8d, 0x05, 0xeb, 0x0b, 0x00, 0x00,
				0x48, 0x89, 0x45, 0xd8,
				0x48, 0x8b, 0x45, 0xc0,
				0x48, 0x83, 0xc0, 0x08,
				0x48, 0x8b, 0x10,
				0x48, 0x8b, 0x45, 0xd8,
				0x48, 0x89, 0xd6,
				0x48, 0x89, 0xc7,
				0xe8, 0x29, 0xfe, 0xff, 0xff,
				0x48, 0x89, 0x45, 0xd0,
				0x48, 0x8b, 0x45, 0xd0,
				0x48, 0x89, 0xc6,
				0x48, 0x8d, 0x3d, 0xd1, 0x0b, 0x00, 0x00,
				0xb8, 0x00, 0x00, 0x00, 0x00,
				0xe8, 0xd0, 0xfb, 0xff, 0xff,
				0xb8, 0x00, 0x00, 0x00, 0x00,
				0xc9, // To here
				0xc3,
			};

			CHECK(bytes == patched_bytes);
		}

		SUBCASE("create a near jump instruction")
		{
			std::vector<u8> bytes = {
				      0x48, 0x89, 0xC7,  0xE8, 0x67, 0xFE, 0xFF,   0xFF, 0xB8, 0x01, 0x00,  0x00, 0x00, 0x90, 0x90,
				0x90, 0x90, 0x90, 0xC7,  0x45, 0xFC, 0x00, 0x00,   0x00, 0x00, 0xBF, 0x00,  0x00, 0x00, 0x00, 0xE8,
				0x6C, 0xFE, 0xFF, 0xFF,  0x48, 0x8B, 0x45, 0xE0,   0x48, 0x83, 0xC0, 0x08,  0x48, 0x8B, 0x00, 0x48,
				0x8D, 0x15, 0x2A, 0x0E,  0x00, 0x00, 0x48, 0x89,   0xD6, 0x48, 0x89, 0xC7,  0xE8, 0x5F, 0xFE, 0xFF,
				0xFF, 0x85, 0xC0, 0x75,  0x1A, 0x48, 0x8D, 0x05,   0x1D, 0x0E, 0x00, 0x00,  0x48, 0x89, 0xC7, 0xB8,
				0x00, 0x00, 0x00, 0x00,  0xE8, 0x27, 0xFE, 0xFF,   0xFF, 0x83, 0x45, 0xFC,  0x01, 0xEB, 0x13, 0x48,
				0x8D, 0x05, 0x16, 0x0E,  0x00, 0x00, 0x48, 0x89,   0xC7, 0xE8, 0x02, 0xFE,  0xFF, 0xFF, 0x83, 0x6D,
				0xFC, 0x01, 0x83, 0x45,  0xFC, 0x63, 0xE8, 0x35,   0xFE, 0xFF, 0xFF, 0x83,  0xF8, 0x01, 0x74, 0x09,
				0x83, 0x45, 0xFC, 0x08,  0x8B, 0x45, 0xFC, 0xEB,   0x34, 0x83, 0x45, 0xFC,  0x32, 0x81, 0x7D, 0xFC,
				0x96, 0x00, 0x00, 0x00,  0x7E, 0x05, 0x8B, 0x45,   0xFC, 0xEB, 0x22, 0x83,  0x45, 0xFC, 0x0E, 0x8B,
				0x45, 0xFC, 0x89, 0xC6,  0x48, 0x8D, 0x05, 0xE3,   0x0D, 0x00, 0x00, 0x48,  0x89, 0xC7, 0xB8, 0x00,
				0x00, 0x00, 0x00, 0xE8,  0xC8, 0xFD, 0xFF, 0xFF,   0xB8, 0x00, 0x00, 0x00,  0x00, 0xC9, 0xC3, 0x00,
			};

			const u32 original_bytes_count = bytes.size();

			std::vector<std::string> subst = {
				"jmp ; 0xd ; 0xbc"
			};

			std::vector<subst_cmd> commands = subst::parse_subst(subst);
			patch_bytes(bytes, commands, false);

			CHECK(bytes.size() == original_bytes_count);

			std::vector<u8> patched_bytes = {
				      0x48, 0x89, 0xC7,  0xE8, 0x67, 0xFE, 0xFF,   0xFF, 0xB8, 0x01, 0x00,  0x00, 0x00, 0xE9, 0xAA,
				0x00, 0x00, 0x00, 0xC7,  0x45, 0xFC, 0x00, 0x00,   0x00, 0x00, 0xBF, 0x00,  0x00, 0x00, 0x00, 0xE8,
				0x6C, 0xFE, 0xFF, 0xFF,  0x48, 0x8B, 0x45, 0xE0,   0x48, 0x83, 0xC0, 0x08,  0x48, 0x8B, 0x00, 0x48,
				0x8D, 0x15, 0x2A, 0x0E,  0x00, 0x00, 0x48, 0x89,   0xD6, 0x48, 0x89, 0xC7,  0xE8, 0x5F, 0xFE, 0xFF,
				0xFF, 0x85, 0xC0, 0x75,  0x1A, 0x48, 0x8D, 0x05,   0x1D, 0x0E, 0x00, 0x00,  0x48, 0x89, 0xC7, 0xB8,
				0x00, 0x00, 0x00, 0x00,  0xE8, 0x27, 0xFE, 0xFF,   0xFF, 0x83, 0x45, 0xFC,  0x01, 0xEB, 0x13, 0x48,
				0x8D, 0x05, 0x16, 0x0E,  0x00, 0x00, 0x48, 0x89,   0xC7, 0xE8, 0x02, 0xFE,  0xFF, 0xFF, 0x83, 0x6D,
				0xFC, 0x01, 0x83, 0x45,  0xFC, 0x63, 0xE8, 0x35,   0xFE, 0xFF, 0xFF, 0x83,  0xF8, 0x01, 0x74, 0x09,
				0x83, 0x45, 0xFC, 0x08,  0x8B, 0x45, 0xFC, 0xEB,   0x34, 0x83, 0x45, 0xFC,  0x32, 0x81, 0x7D, 0xFC,
				0x96, 0x00, 0x00, 0x00,  0x7E, 0x05, 0x8B, 0x45,   0xFC, 0xEB, 0x22, 0x83,  0x45, 0xFC, 0x0E, 0x8B,
				0x45, 0xFC, 0x89, 0xC6,  0x48, 0x8D, 0x05, 0xE3,   0x0D, 0x00, 0x00, 0x48,  0x89, 0xC7, 0xB8, 0x00,
				0x00, 0x00, 0x00, 0xE8,  0xC8, 0xFD, 0xFF, 0xFF,   0xB8, 0x00, 0x00, 0x00,  0x00, 0xC9, 0xC3, 0x00,
			};

			CHECK(bytes == patched_bytes);
		}
	}
}
