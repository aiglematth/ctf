add-symbol-file sym/symbols
set follow-fork-mode child
set print pretty on
b main
r
b*0x5555555557ca
c
