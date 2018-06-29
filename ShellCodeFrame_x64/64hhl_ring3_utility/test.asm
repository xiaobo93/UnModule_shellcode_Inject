.data


.code


EXTRN ShellCode_Entry:PROC   ;this function is in c



PUBLIC FUNC					;export FUNC function to c

FUNC proc 
MOV RAX, 1234
RET 
FUNC endp
 
 
PUBLIC  AlignRSPAndCallShEntry   ; Marking AlignRSP as PUBLIC allows for the function to be called as an extern in our C code.
 
AlignRSPAndCallShEntry PROC
 push rsi						; Preserve RSI since we're stomping on it
 mov  rsi, rsp					; Save the value of RSP so it can be restored
 and  rsp, 0FFFFFFFFFFFFFFF0h	; Align RSP to 16 bytes
 sub  rsp, 020h					; Allocate homing space for ExecutePayload
 call ShellCode_Entry			; Call the entry point of the payload
 mov  rsp, rsi					; Restore the original value of RSP
 pop  rsi						; Restore RSI
 ret							; Return to caller
AlignRSPAndCallShEntry ENDP



PUBLIC get_kernel32_peb_64

get_kernel32_peb_64 PROC

mov rax,30h
mov rax,gs:[rax] ;
mov rax,[rax+60h] ;
mov rax, [rax+18h] ;
mov rax, [rax+10h] ;
mov rax,[rax] ;
mov rax,[rax] ;
mov rax,[rax+30h] ;DllBase
ret

get_kernel32_peb_64 ENDP


PUBLIC get_ntdll_peb_64

get_ntdll_peb_64 PROC

mov rax,30h
mov rax,gs:[rax] ;
mov rax,[rax+60h] ;
mov rax, [rax+18h] ;
mov rax, [rax+10h] ;
mov rax,[rax] ;
mov rax,[rax+30h] ;
ret

get_ntdll_peb_64 ENDP




PUBLIC MyShellCodeFinalEnd

MyShellCodeFinalEnd PROC
	xor rax,rax
	ret
MyShellCodeFinalEnd ENDP
 
END
 
 
 
