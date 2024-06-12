#include "Hex.hpp"
#include "Search.hpp"
#include "Types.hpp"

#include <capstone/capstone.h>
#include <cassert>
#include <clipp.h>
#include <cstddef>
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

	bool disassemble = false;
	bool disas_32bit_mode = false;

	auto search_mode = (
		clipp::command("search").set(selected_mode, mode::search),
		clipp::option("-d", "--disas").set(disassemble).doc("attempt to disassemble the hex string"),
		clipp::option("-32").set(disas_32bit_mode).doc("enable 32-bit mode"),
		clipp::value("hex string", hex_string).doc("search for a hex string in the binary")
	);

	auto patch_mode = (
		clipp::command("patch").set(selected_mode, mode::patch),
		clipp::value("subst file", subst_file_path).doc("subst file to use for patching")
	);

	auto cli = (
		(search_mode | patch_mode),
		clipp::value("binary file", binary_file_path)
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
				std::vector<u8> bytes = hex_str_to_int(hex_string);
				disasm_bytes(bytes, 0x0, disas_32bit_mode);

				std::cout << "\nLocations:\n";
			}

			std::vector<size_t> locations = search_bytes(binary_data, hex_string);
			print_hex_vec(locations);
			break;
		}

		case mode::patch:
		{

			break;
		}

		case mode::help:
			assert(1 == 0 && "You shouldn't be here");
			break;
	}

	return 0;
}
