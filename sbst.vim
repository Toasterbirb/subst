if exists("b:current_syntax")
	finish
endif

syn match substCount /[0-9]/
syn match substHex /0x[A-Za-z0-9]\+/
syn match substHex /[A-Za-z0-9]\{2}/
syn match substSemicolon /;/

syn match substComment /#.*/
syn keyword substCommand rep repat nop nopi inv

syn case match

hi def link substComment Comment
hi def link substCommand Statement
hi def link substHex Number
hi def link substCount Constant
hi def link substSemicolon Delimiter
