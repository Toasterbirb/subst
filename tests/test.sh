#!/bin/bash

readonly TEST_PROGRAM_PATH="./pass_check"
readonly TEST_PROGRAM_MD5_CHECKSUM="4af65211188a58effc2035942d4c6743"
readonly PATCHED_TEST_PROGRAM_PATH="./pass_check.patched"

readonly COMPARISON_PROGRAM_SUBST_FILE_PATH="./comparison.sbst"
readonly COMPARISON_PROGRAM_PATH="./comparison"
readonly COMPARISON_PROGRAM_MD5_CHECKSUM="ba1f05d713beecb408aaafb73c5d54f9"
readonly PATCHED_COMPARISON_PROGRAM_PATH="./comparison.patched"

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
./subst patch -f "$TEST_PROGRAM_PATH"

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

if [ "$(md5sum $COMPARISON_PROGRAM_PATH | cut -d ' ' -f 1)" != "$COMPARISON_PROGRAM_MD5_CHECKSUM" ]
then
	echo "WARNING: The checksum of the test program does not match. The tests might not work as intended."
fi

# Patch the comparison program
./subst patch -f -s "$COMPARISON_PROGRAM_SUBST_FILE_PATH" "$COMPARISON_PROGRAM_PATH"

if [ ! -f "$PATCHED_COMPARISON_PROGRAM_PATH" ]
then
	echo "The patche version of the comparison test file is missing"
	exit 2
fi

chmod +x "$PATCHED_COMPARISON_PROGRAM_PATH"

OUTPUT="$($PATCHED_COMPARISON_PROGRAM_PATH a b c)"
RETURN_VALUE=$?

if [ "$OUTPUT" != "Correct!" ]
then
	echo "Incorrect test output: $OUTPUT"
	exit 1
fi

if [ $RETURN_VALUE -ne 0 ]
then
	echo "Incorrect return value: $RETURN_VALUE"
	exit 1
fi

# Run doctest unit tests
set -e
./subst test

echo "Test passed successfully!"
