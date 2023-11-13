.data
    
EXTERN FnAllocvm_num:DWORD
EXTERN FnWrvm_num:DWORD
EXTERN FnProtvm_num:DWORD
EXTERN FnCrth_num:DWORD          
EXTERN FnSo_num:DWORD
    
EXTERN instruct_addr_of_s:QWORD 

.code
FnAllocvm proc
		mov r10, rcx
		mov eax, FnAllocvm_num      
		jmp qword ptr[instruct_addr_of_s]                        
		ret                             
FnAllocvm endp

FnWrvm proc
		mov r10, rcx
		mov eax, FnWrvm_num      
		jmp qword ptr[instruct_addr_of_s]                        
		ret                             
FnWrvm endp

FnProtvm proc
		mov r10, rcx
		mov eax, FnProtvm_num      
		jmp qword ptr[instruct_addr_of_s]                        
		ret                             
FnProtvm endp

FnCrth proc
		mov r10, rcx
		mov eax, FnCrth_num      
		jmp qword ptr[instruct_addr_of_s]                        
		ret                             
FnCrth endp

FnSo proc
		mov r10, rcx
		mov eax, FnSo_num      
		jmp qword ptr[instruct_addr_of_s]                        
		ret                             
FnSo endp

end