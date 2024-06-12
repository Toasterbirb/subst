# A testing .sbt file for patching the included pass_check program
# The goal is to make the program output "correct password: 5"

# Bypass the argument count check
rep ; 83 7d ec 02 ; 83 7d ec 01

# Don't check the password at all
nop ; e8 5f fe ff ff

# Patch out an addition that adds 99 to the output value
nop ; 0x1232 ; 4

# Patch out an addition that adds 50 to the output value
nop ; 83 45 fc 32

# Patch an addition from 14 to 4
repat ; 0x125b ; 83 45 fc 04

# Inver the if-stement that gets its result with srand()
inv ; 0x123e
