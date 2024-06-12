#include <stdio.h>

int main(int argc, char** argv)
{
	if (argc > 2)
	{
		printf("Wrong!\n");
		return 1;
	}

	if (argc <= 2)
	{
		printf("Still wrong!\n");
		return 2;
	}

	if (argv[0][0] < 125)
	{
		printf("Quite possibly wrong!\n");
		return 3;
	}


	printf("Correct!\n");

	return 0;
}
