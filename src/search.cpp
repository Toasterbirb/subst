#include "Hex.hpp"
#include "Search.hpp"

#include <iostream>

namespace subst
{
	std::vector<size_t> search_bytes(std::span<u8> bytes, const std::string& hex_string)
	{
		std::vector<u8> bytes_to_find = hex_str_to_bytes(hex_string);
		return search_bytes(bytes, bytes_to_find);
	}

	std::vector<size_t> search_bytes(std::span<u8> bytes, const std::vector<u8>& bytes_to_find)
	{
		std::vector<size_t> locations;

		if (bytes_to_find.empty())
		{
			std::cout << "The hex string cannot be empty\n";
			return locations;
		}

		// Locate the byte array in the binary
		for (size_t i = 0; i < bytes.size(); ++i)
		{
			if (bytes[i] == bytes_to_find[0] && bytes.size() >= i + bytes_to_find.size())
			{
				// Check if the entire hex string was found
				bool hex_string_found = true;
				for (size_t j = 1; j < bytes_to_find.size(); ++j)
				{
					if (bytes[i + j] != bytes_to_find[j])
					{
						hex_string_found = false;
						break;
					}
				}

				if (hex_string_found)
					locations.push_back(i);
			}
		}

		return locations;
	}
}
