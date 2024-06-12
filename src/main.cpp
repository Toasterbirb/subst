#include "Hex.hpp"
#include "Patch.hpp"
#include "Search.hpp"
#include "Types.hpp"

#include <capstone/capstone.h>
#include <cassert>
#include <clipp.h>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <inttypes.h>
#include <iostream>
#include <stdio.h>

int main(int argc, char** argv)
{
	enum class mode { search, patch, help };
	mode selected_mode = mode::help;

	std::string subst_file_path;
	std::string binary_file_path;
	std::string hex_string;

	// Search options
	bool disassemble = false;
	bool disas_32bit_mode = false;

	// Patch options
	bool overwrite_patched_file = false;

	auto search_mode = (
		clipp::command("search").set(selected_mode, mode::search),
		clipp::option("-d", "--disas").set(disassemble).doc("attempt to disassemble the hex string"),
		clipp::value("hex", hex_string).doc("search for a hex string in the binary")
	);

	auto patch_mode = (
		clipp::command("patch").set(selected_mode, mode::patch),
		clipp::option("-f").set(overwrite_patched_file).doc("overwrite a patched file if one already exists"),
		clipp::value("subst file", subst_file_path).doc("path to a subst file to use for patching")
	);

	auto cli = (
		(search_mode | patch_mode),
		clipp::option("-32").set(disas_32bit_mode).doc("enable 32-bit mode"),
		clipp::value("binary", binary_file_path).doc("path to a binary file to patch or query")
	);

	if (!clipp::parse(argc, argv, cli))
	{
		std::cout << clipp::make_man_page(cli, argv[0]);
		return 1;
	}

	std::ifstream bin_file(binary_file_path, std::ios::in | std::ios::binary | std::ios::out);
	if (!bin_file.is_open())
	{
		std::cout << "Couldn't open file: " << binary_file_path << "\n";
		return 1;
	}

	std::vector<u8> binary_data;

	// Figure out the size of the file
	bin_file.seekg(0, std::ios::end);
	binary_data.resize(bin_file.tellg());

	// Return to the beginning of the file
	bin_file.seekg(0, std::ios::beg);

	// Read the binary file in
	bin_file.read((char*)&binary_data[0], binary_data.size());

	switch (selected_mode)
	{
		case mode::search:
		{
			if (disassemble)
			{
				std::vector<u8> bytes = subst::hex_str_to_int(hex_string);
				subst::disasm_bytes(bytes, 0x0, disas_32bit_mode);

				std::cout << "\nLocations:\n";
			}

			std::vector<size_t> locations = subst::search_bytes(binary_data, hex_string);
			subst::print_hex_vec(locations);
			break;
		}

		case mode::patch:
		{
			const std::string patched_file_path = binary_file_path + ".patched";

			if (std::filesystem::exists(patched_file_path) && !overwrite_patched_file)
			{
				std::cout	<< "A patched file already exists at " << patched_file_path << '\n'
							<< "Overwrite the file? (y/n): ";

				char answer;
				std::cin >> answer;

				switch (answer)
				{
					case 'y':
					case 'Y':
						break;

					default:
						return 0;
				}
			}

			// Make sure that we are not writing over an existing patched file
			std::filesystem::remove(patched_file_path);

			std::vector<subst::subst_cmd> subst_commands = subst::parse_subst_file(subst_file_path);
			subst::patch_bytes(binary_data, subst_commands, disas_32bit_mode);

			// Write the patched binary data into a new file
			std::ofstream patched_file(patched_file_path, std::ios::app);

			for (u8 byte : binary_data)
				patched_file.write(reinterpret_cast<char*>(&byte), sizeof(u8));

			break;
		}

		case mode::help:
			assert(1 == 0 && "You shouldn't be here");
			break;
	}

	return 0;
}
