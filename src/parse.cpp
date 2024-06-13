#include "Hex.hpp"
#include "Parse.hpp"

#include <doctest/doctest.h>
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

			// Remove all tab indentation
			std::erase(line, '\t');

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
				commands.clear(); // Wipe the command list so that nothing will be done to the binary
				return commands;
			}

			// Parse the tokens
			commands.emplace_back(parse_subst_tokens(tokens, original_line));
		}

		return commands;
	}

	TEST_CASE("parsing")
	{
		SUBCASE("comments")
		{
			std::vector<std::string> subst = {
				"# comment at the beginning of the line",
				"    # comment with space indentation",
				" #asdf",
				"			# comment with tab indentation",
				"  	 			 # comment with tab and space indentation",
				" # cömment with funny letters äääää",
				" # some comment with 1234 numbers"
			};

			std::vector<subst::subst_cmd> commands = subst::parse_subst(subst);
			CHECK(commands.empty());
		}

		SUBCASE("rep")
		{
			std::vector<std::string> subst = {
				"rep ; 7f45 4c46 ; 0201 0103	# Replace bytes with the default grouping of xxd",
				"	rep ; 0201 0103;0000 0000       # The same but with a different level of indentation and spacing",
				"",
				"rep ; 1 ; 1  # Test singular byte values with no leading zeroes"
			};

			std::vector<subst::subst_cmd> commands = subst::parse_subst(subst);
			CHECK(commands.size() == 3);

			CHECK(commands[0].mode == subst_cmd::mode::rep);
			CHECK(commands[0].bytes == std::vector<u8>{ 0x7f, 0x45, 0x4c, 0x46 });
			CHECK(commands[0].replacement_bytes == std::vector<u8>{ 0x02, 0x01, 0x01, 0x03 });
			CHECK(commands[0].location == 0);
			CHECK(commands[0].count == 0);

			CHECK(commands[1].mode == subst_cmd::mode::rep);
			CHECK(commands[1].bytes == std::vector<u8>{ 0x02, 0x01, 0x01, 0x03 });
			CHECK(commands[1].replacement_bytes == std::vector<u8>{ 0x00, 0x00, 0x00, 0x00 });
			CHECK(commands[1].location == 0);
			CHECK(commands[1].count == 0);

			CHECK(commands[2].mode == subst_cmd::mode::rep);
			CHECK(commands[2].bytes == std::vector<u8>{ 0x1 });
			CHECK(commands[2].replacement_bytes == std::vector<u8>{ 0x1 });
			CHECK(commands[2].location == 0);
			CHECK(commands[2].count == 0);
		}

		SUBCASE("repat")
		{
			std::vector<std::string> subst = {
				"repat ; 0x52 ; 01 03",
				"repat ; 0x1 ; 0000 0000"
			};

			std::vector<subst::subst_cmd> commands = subst::parse_subst(subst);
			CHECK(commands.size() == 2);

			CHECK(commands[0].mode == subst_cmd::mode::repat);
			CHECK(commands[0].bytes.empty());
			CHECK(commands[0].replacement_bytes == std::vector<u8>{ 0x01, 0x03 });
			CHECK(commands[0].location == 0x52);
			CHECK(commands[0].count == 0);

			CHECK(commands[1].mode == subst_cmd::mode::repat);
			CHECK(commands[1].bytes.empty());
			CHECK(commands[1].replacement_bytes == std::vector<u8>{ 0x00, 0x00, 0x00, 0x00 });
			CHECK(commands[1].location == 0x1);
			CHECK(commands[1].count == 0);
		}

		SUBCASE("nop")
		{
			std::vector<std::string> subst = {
				"nop ; 7f45 4c46",
				"nop ; 01 03 00 00",
				"nop ; 0x5 ; 8",
				"nop ; 0 ; 0"
			};

			std::vector<subst::subst_cmd> commands = subst::parse_subst(subst);
			CHECK(commands.size() == 4);

			CHECK(commands[0].mode == subst_cmd::mode::nop);
			CHECK(commands[0].bytes == std::vector<u8>{ 0x7f, 0x45, 0x4c, 0x46 });
			CHECK(commands[0].replacement_bytes.empty());
			CHECK(commands[0].location == 0);
			CHECK(commands[0].count == 0);

			CHECK(commands[1].mode == subst_cmd::mode::nop);
			CHECK(commands[1].bytes == std::vector<u8>{ 0x01, 0x03, 0x00, 0x00 });
			CHECK(commands[1].replacement_bytes.empty());
			CHECK(commands[1].location == 0);
			CHECK(commands[1].count == 0);

			CHECK(commands[2].mode == subst_cmd::mode::nop);
			CHECK(commands[2].bytes.empty());
			CHECK(commands[2].replacement_bytes.empty());
			CHECK(commands[2].location == 0x5);
			CHECK(commands[2].count == 8);

			CHECK(commands[3].mode == subst_cmd::mode::nop);
			CHECK(commands[3].bytes.empty());
			CHECK(commands[3].replacement_bytes.empty());
			CHECK(commands[3].location == 0);
			CHECK(commands[3].count == 0);
		}

		SUBCASE("nopi")
		{
			std::vector<std::string> subst = {
				"nopi ; 0x2",
				"nopi ; 0x6 ; 4"
			};

			std::vector<subst_cmd> commands = subst::parse_subst(subst);
			CHECK(commands.size() == 2);

			CHECK(commands[0].mode == subst_cmd::mode::nopi);
			CHECK(commands[0].bytes.empty());
			CHECK(commands[0].replacement_bytes.empty());
			CHECK(commands[0].location == 0x2);
			CHECK(commands[0].count == 1);

			CHECK(commands[1].mode == subst_cmd::mode::nopi);
			CHECK(commands[1].bytes.empty());
			CHECK(commands[1].replacement_bytes.empty());
			CHECK(commands[1].location == 0x6);
			CHECK(commands[1].count == 4);
		}

		SUBCASE("inv")
		{
			std::vector<std::string> subst = {
				"inv ; 0x2",
				"inv ; 0xaaaa"
			};

			std::vector<subst::subst_cmd> commands = subst::parse_subst(subst);
			CHECK(commands.size() == 2);

			CHECK(commands[0].mode == subst_cmd::mode::inv);
			CHECK(commands[0].bytes.empty());
			CHECK(commands[0].replacement_bytes.empty());
			CHECK(commands[0].location == 0x2);
			CHECK(commands[0].count == 0);

			CHECK(commands[1].mode == subst_cmd::mode::inv);
			CHECK(commands[1].bytes.empty());
			CHECK(commands[1].replacement_bytes.empty());
			CHECK(commands[1].location == 0xaaaa);
			CHECK(commands[1].count == 0);
		}
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

			case subst_cmd::mode::nopi:
			{
				if (tokens.size() > 3)
				{
					std::cout << "invalid mnemonic nop: " << original_line << "\n";
					exit(1);
				}

				// by default: nopi ; location
				cmd.location = std::stoi(tokens[1], 0, 16);
				cmd.count = 1;

				// if 3 tokens: nopi ; location ; amount_of_bytes_to_nop
				if (tokens.size() == 3)
					cmd.count = std::stoi(tokens[2]);

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
