#!/bin/bash

readonly EXPECTED_RETURN_VALUE=42

TEST_BINS="$(find . -maxdepth 1 -iname 't_*' ! -iname '*.patched')"
if [ -z "$TEST_BINS" ]
then
	echo "No test binaries were found. Make sure that you are in the build directory and have run 'make'"
	exit 1
fi

rm -vf ./*.patched

for i in $TEST_BINS
do
	echo " >> $i"
	subst patch -s "${i//t_/}.sbst" "$i"
	"$i.patched"
	RETURN_VALUE=$?
	if [ $RETURN_VALUE -ne $EXPECTED_RETURN_VALUE ]
	then
		echo -e "\e[1;31mFAIL\e[0m (returned $RETURN_VALUE)"
	else
		echo -e "\e[1;32mPASS\e[0m"
	fi
done
