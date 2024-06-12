#include "Hex.hpp"
#include "Parse.hpp"

#include <fstream>
#include <iostream>
#include <regex>

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

	std::vector<std::string> read_file(const std::string& file_path)
	{
		// Read the file line by line
		std::ifstream file(file_path);
		std::string line;

		std::vector<std::string> lines;

		while (std::getline(file, line))
			lines.emplace_back(line);

		return lines;
	}

	std::vector<subst_cmd> parse_subst(const std::vector<std::string>& subst_lines)
	{
		std::vector<subst_cmd> commands;

		// Read the subst file in line by line (ignoring empty lines and comments)
		for (std::string line : subst_lines)
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
			commands.emplace_back(parse_subst_tokens(tokens, original_line));
		}

		return commands;
	}

	subst_cmd parse_subst_tokens(const std::vector<std::string>& tokens, const std::string& original_line)
	{
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

		return cmd;
	}
}
