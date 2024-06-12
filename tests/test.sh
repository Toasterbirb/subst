#!/bin/bash

readonly SUBST_FILE_PATH="./pass_check.sbt"
readonly TEST_PROGRAM_PATH="./pass_check"
readonly TEST_PROGRAM_MD5_CHECKSUM="4af65211188a58effc2035942d4c6743"
readonly PATCHED_TEST_PROGRAM_PATH="./pass_check.patched"

if [ ! -f "$TEST_PROGRAM_PATH" ]
then
	echo "Test binary not found"
	exit 1
fi

if [ "$(md5sum $TEST_PROGRAM_PATH | cut -d ' ' -f 1)" != "$TEST_PROGRAM_MD5_CHECKSUM" ]
then
	echo "WARNING: The checksum of the test program does not match. The tests might not work as intended."
fi

# Patch the program
./subst patch  -f "$SUBST_FILE_PATH" "$TEST_PROGRAM_PATH"

if [ ! -f "$PATCHED_TEST_PROGRAM_PATH" ]
then
	echo "The patched version of the test file is missing!"
	exit 1
fi

# Test the patched program
chmod +x "$PATCHED_TEST_PROGRAM_PATH"

# Run the program with no arguments ( it should still work ;) )
OUTPUT=$($PATCHED_TEST_PROGRAM_PATH)
RETURN_VALUE=$?

if [ "$OUTPUT" != "correct password: 5" ]
then
	echo "Incorrect test output: $OUTPUT"
	exit 1
fi

if [ $RETURN_VALUE -ne 0 ]
then
	echo "Incorrect return value: $RETURN_VALUE"
	exit 1
fi

echo "Test passed successfully!"
