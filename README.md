# subst

Find hex strings in a binary and replace bytes with an interpreted language. For usage information run the compiled binary with no arguments

## subst file format
```
rep ; bytes ; replacement_bytes					# Replace all instances of the byte array with the given byte array
repat ; location ; replacement_bytes			# Replace bytes at the given location with the given bytes
nop ; bytes										# NOP all instances of the given byte array
nop ; location ; amount_of_bytes_to_replace		# Replace a certain amount of bytes with NOP starting from the given location
nopi ; location                                 # NOP out an instruction at the given location
nopi ; location ; amount_of_bytes_to_nop        # NOP out a certain amount of instruction at the given location
inv ; location									# Invert a conditional at the given location
```
A few example files can be found in the tests directory

## Building

### External dependencies
- capstone
- doctest

Build the project with cmake by running the following commands
```sh
mkdir build
cd build
cmake ..
make -j$(nproc)
```

## Installation
To install subst to /usr/local/bin, run the following command
```sh
make install
```
You can customize the installation *PREFIX* and *DESTDIR* variables normally with cmake and make.
