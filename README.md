# subst

Find hex strings in a binary and replace bytes with an interpreted language. For usage information run the compiled binary with no arguments

## subst file format
```
rep ; bytes ; replacement_bytes              # Replace all instances of the byte array with the given byte array
repat ; location ; replacement_bytes         # Replace bytes at the given location with the given bytes
nop ; bytes                                  # NOP all instances of the given byte array
nop ; location ; amount_of_bytes_to_replace  # Replace a certain amount of bytes with NOP starting from the given location
nopi ; location                              # NOP out an instruction at the given location
nopi ; location ; amount_of_bytes_to_nop     # NOP out a certain amount of instruction at the given location
inv ; location                               # Invert a conditional at the given location
jmp ; location ; destination                 # Create a jmp instruction to the given location that jumps to the destination address
```
# Example
Imagine the following program:
```c
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char** argv)
{
	if (argc != 2)
	{
		printf("%s\n", "Usage: impossible [some number]");
		return 1;
	}

	int answer = 42;
	int user_input = atoi(argv[1]);

	if (user_input == answer)
		user_input++;

	if (user_input == answer)
		printf("%s\n", "You win!");
	else
		printf("%s\n", "You lose!");

	return 0;
}
```
What argument would you have to give to the program to get the winning output? If your answer is "I don't know", we can fix that problem with `subst`.

The main function of the "impossible" program looks like this in radare:
```
╭ 131: int main (uint32_t argc, char **argv);
│           ; arg uint32_t argc @ rdi
│           ; arg char **argv @ rsi
│           ; var uint32_t var_4h @ rbp-0x4
│           ; var int64_t var_8h @ rbp-0x8
│           ; var uint32_t var_14h @ rbp-0x14
│           ; var char **str @ rbp-0x20
│           0x00001175      55             push rbp
│           0x00001176      4889e5         mov rbp, rsp
│           0x00001179      4883ec20       sub rsp, 0x20
│           0x0000117d      897dec         mov dword [var_14h], edi    ; argc
│           0x00001180      488975e0       mov qword [str], rsi        ; argv
│           0x00001184      837dec02       cmp dword [var_14h], 2
│       ╭─< 0x00001188      7416           je 0x11a0
│       │   0x0000118a      488d05770e..   lea rax, str.Usage:_impossible__some_number_ ; 0x2008 ; "Usage: impossible [some number]"
│       │   0x00001191      4889c7         mov rdi, rax                ; const char *s
│       │   0x00001194      e897feffff     call sym.imp.puts           ; int puts(const char *s)
│       │   0x00001199      b801000000     mov eax, 1
│      ╭──< 0x0000119e      eb56           jmp 0x11f6
│      ││   ; CODE XREF from main @ 0x1188(x)
│      │╰─> 0x000011a0      c745fc2a00..   mov dword [var_4h], 0x2a    ; '*'
│      │    0x000011a7      488b45e0       mov rax, qword [str]
│      │    0x000011ab      4883c008       add rax, 8
│      │    0x000011af      488b00         mov rax, qword [rax]
│      │    0x000011b2      4889c7         mov rdi, rax                ; const char *str
│      │    0x000011b5      e886feffff     call sym.imp.atoi           ; int atoi(const char *str)
│      │    0x000011ba      8945f8         mov dword [var_8h], eax
│      │    0x000011bd      8b45f8         mov eax, dword [var_8h]
│      │    0x000011c0      3b45fc         cmp eax, dword [var_4h]
│      │╭─< 0x000011c3      7504           jne 0x11c9
│      ││   0x000011c5      8345f801       add dword [var_8h], 1
│      ││   ; CODE XREF from main @ 0x11c3(x)
│      │╰─> 0x000011c9      8b45f8         mov eax, dword [var_8h]
│      │    0x000011cc      3b45fc         cmp eax, dword [var_4h]
│      │╭─< 0x000011cf      7511           jne 0x11e2
│      ││   0x000011d1      488d05500e..   lea rax, str.You_win_       ; 0x2028 ; "You win!"
│      ││   0x000011d8      4889c7         mov rdi, rax                ; const char *s
│      ││   0x000011db      e850feffff     call sym.imp.puts           ; int puts(const char *s)
│     ╭───< 0x000011e0      eb0f           jmp 0x11f1
│     │││   ; CODE XREF from main @ 0x11cf(x)
│     ││╰─> 0x000011e2      488d05480e..   lea rax, str.You_lose_      ; 0x2031 ; "You lose!"
│     ││    0x000011e9      4889c7         mov rdi, rax                ; const char *s
│     ││    0x000011ec      e83ffeffff     call sym.imp.puts           ; int puts(const char *s)
│     ││    ; CODE XREF from main @ 0x11e0(x)
│     ╰───> 0x000011f1      b800000000     mov eax, 0
│      │    ; CODE XREF from main @ 0x119e(x)
│      ╰──> 0x000011f6      c9             leave
╰           0x000011f7      c3             ret
```
There are multiple ways we could approach this situation. One way would be to skip the portion of the code that increments the user input making the challenge (maybe) impossible. This can be achieved with the following subst code:
```
nopi ; 0x000011c5
```
The code above would patch out the instruction at 0x000011c5, which in this case would be `add dword [var_8h], 1`. The entire patching process would look like this (assuming the name of the binary is "impossible"):
```sh
toasterbirb@tux /tmp/subst $ ls
impossible  impossible.c  impossible.sbst
toasterbirb@tux /tmp/subst $ cat impossible.sbst
nopi ; 0x000011c5
toasterbirb@tux /tmp/subst $ subst patch ./impossible
patching out a add instruction at 0x11c5
toasterbirb@tux /tmp/subst $ ls
impossible  impossible.c  impossible.patched  impossible.sbst
toasterbirb@tux /tmp/subst $ chmod +x impossible.patched
toasterbirb@tux /tmp/subst $ ./impossible.patched 42
You win!
toasterbirb@tux /tmp/subst $
```
Note the name of the subst file `impossible.sbst`. The file is named after the binary we are going to patch. However a custom `sbst` file name can be used with the `-s` argument.

Here's another way to solve the puzzle above:
```
jmp ; 0x0000117d ; 0x000011d1
```
This time we are creating a jump to the beginning of the program that skips straight to the winning message without even checking the user input. The patched program would work like this:
```
toasterbirb@tux /tmp/subst $ subst patch ./impossible
creating a short jump 0x117d -> 0x11d1 (84 bytes)
toasterbirb@tux /tmp/subst $ chmod +x impossible.patched
toasterbirb@tux /tmp/subst $ ./impossible.patched
You win!
toasterbirb@tux /tmp/subst $
```
The patched program looks like this in radare:
```
╭ 34: int main (int argc, char **argv, char **envp);
│           0x00001175      55             push rbp
│           0x00001176      4889e5         mov rbp, rsp
│           0x00001179      4883ec20       sub rsp, 0x20
│       ╭─< 0x0000117d      eb52           jmp 0x11d1
..
      │││   ; CODE XREF from main @ +0x13(x)
      │││   ; CODE XREF from main @ +0x4e(x)
│     │││   ; CODE XREF from main @ 0x117d(x)
│     ││╰─> 0x000011d1      488d05500e..   lea rax, str.You_win_       ; 0x2028 ; "You win!"
│     ││    0x000011d8      4889c7         mov rdi, rax                ; const char *s
│     ││    0x000011db      e850feffff     call sym.imp.puts           ; int puts(const char *s)
│     ││╭─< 0x000011e0      eb0f           jmp 0x11f1
      │││   ; CODE XREF from main @ +0x5a(x)
..
│     │ │   ; CODE XREF from main @ 0x11e0(x)
│     │ ╰─> 0x000011f1      b800000000     mov eax, 0
│     │     ; CODE XREF from main @ +0x29(x)
│     ╰───> 0x000011f6      c9             leave
╰           0x000011f7      c3             ret
```

In more complicated cases the subst file might be longer. You can have as many commands as you'd like and they are interpreted line by line sequentially. The file format also supports comments with the `#` character. Also all whitespace and tabs get stripped out, so use them freely

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
