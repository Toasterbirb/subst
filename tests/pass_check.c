#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// If everything goes correctly, this program
// should output "correct password: 5" and exit with code 0

int main(int argc, char** argv)
{
	if (argc != 2)
	{
		printf("%s\n", "Usage pass_check <password>");
		return 1;
	}

	int out_number = 0;
	srand(0);

	if (!strcmp(argv[1], "password"))
	{
		printf("correct password: ");
		out_number++;
	}
	else
	{
		printf("wrong password :(\n");
		out_number--;
	}

	// Make the number too big
	out_number += 99;

	// Exit on random occasions
	if (rand() != 1)
	{
		out_number += 8;
		return out_number;
	}

	// Modify the out_number more
	out_number += 50;
	if (out_number > 150)
		return out_number;

	// At this point the out_number should actually be 1,
	// so to reach 5, 4 should be added to the value here
	// however an incorrect value is added, so the value needs to be patched to 4
	out_number += 14;

	// Print the result
	printf("%d\n", out_number);

	return 0;
}
