push rcx
mov r11, 0xaaaaaaaaaaaaaaaa
mov rcx, 0xbbbbbbbbbbbbbbbb
sub rsp, 0x20
call r11
add rsp, 0x20
pop rcx
mov r11, 0xcccccccccccccccc
jmp r11