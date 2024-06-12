#pragma once

#include "Types.hpp"

#include <span>
#include <string>
#include <vector>

// Attempt to find a string of hex values from a byte array
// Returns a list of found locations
std::vector<size_t> search_bytes(std::span<u8> bytes, const std::string& hex_string);
