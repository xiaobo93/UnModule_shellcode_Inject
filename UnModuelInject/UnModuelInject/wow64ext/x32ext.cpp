#include "x32ext.h"
#ifndef _WIN64
#include <tchar.h>
#include <Shlwapi.h>
#include "wow64ext.h"

#pragma comment(lib, "Shlwapi.lib")

enum  InjectResult{
	OK,
	Error_NoSuchFile,
	Error_OpenProcess,
	Error_VirtualAllocEx,
	Error_GetProcAddress,
	Error_WriteProcessMemory,
	Error_CreateRemoteThread
};

typedef struct _UNICODE_STRING {
	USHORT    Length;     //UNICODE占用的内存字节数，个数*2；
	USHORT	  MaximumLength; 
	DWORD64   Buffer;     //注意这里指针的问题
} UNICODE_STRING ,*PUNICODE_STRING;

#define shell_code_x64_len			104
unsigned char shell_code_x64[shell_code_x64_len] = {
	0x48, 0x89, 0x4c, 0x24, 0x08,                               // mov       qword ptr [rsp+8],rcx 
	0x57,                                                       // push      rdi
	0x48, 0x83, 0xec, 0x20,                                     // sub       rsp,20h
	0x48, 0x8b, 0xfc,                                           // mov       rdi,rsp
	0xb9, 0x08, 0x00, 0x00, 0x00,                               // mov       ecx,8
	0xb8, 0xcc, 0xcc, 0xcc, 0xcc,                               // mov       eac,0CCCCCCCCh
	0xf3, 0xab,                                                 // rep stos  dword ptr [rdi]
	0x48, 0x8b, 0x4c, 0x24, 0x30,                               // mov       rcx,qword ptr [__formal]
	0x49, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov       r9,0  //PVOID*  BaseAddr opt
	0x49, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov       r8,0  //PUNICODE_STRING Name
	0x48, 0xba, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov       rdx,0
	0x48, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov       rcx,0
	0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov       rax,0 
	0xff, 0xd0,                                                 // call      rax   LdrLoadDll
	0x48, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov       rcx,0
	0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov       rax,0
	0xff, 0xd0                                                  // call      rax		RtlExitUserThread
};

InjectResult Wow64Injectx64Ex(HANDLE hProcess, LPCTSTR lpDllFilePath)
{
	size_t file_path_mem_length = (size_t)::_tcslen(lpDllFilePath);
	size_t paramemter_size = (file_path_mem_length+1)*sizeof(TCHAR) + sizeof(UNICODE_STRING) + sizeof(DWORD64);
	DWORD64 paramemter_mem_addr = (DWORD64)VirtualAllocEx64(hProcess,NULL,paramemter_size,MEM_COMMIT,PAGE_READWRITE);
	DWORD64  shell_code_addr = (DWORD64)VirtualAllocEx64(hProcess,NULL,shell_code_x64_len,MEM_COMMIT,PAGE_EXECUTE_READWRITE);
	if ((!paramemter_mem_addr) || (!shell_code_addr)) {
		return Error_VirtualAllocEx;
	}
	char * paramemter_mem_local = new char[paramemter_size];
	memset(paramemter_mem_local,0,paramemter_size);

	PUNICODE_STRING ptr_unicode_string = (PUNICODE_STRING)(paramemter_mem_local + sizeof(DWORD64));
	ptr_unicode_string->Length = file_path_mem_length *sizeof(TCHAR);
	ptr_unicode_string->MaximumLength = (file_path_mem_length+1)*sizeof(TCHAR);
	wcscpy((WCHAR*)(ptr_unicode_string+1),lpDllFilePath);
	ptr_unicode_string->Buffer = (DWORD64)((char*)paramemter_mem_addr+sizeof(DWORD64)+sizeof(UNICODE_STRING));

	DWORD64 ntdll64 = GetModuleHandle64(L"ntdll.dll");
	DWORD64 ntdll_LdrLoadDll = GetProcAddress64(ntdll64,"LdrLoadDll");
	DWORD64 ntdll_RtlCreateUserThread = GetProcAddress64(ntdll64,"RtlCreateUserThread");
	DWORD64 ntdll_RtlExitThread = GetProcAddress64(ntdll64,"RtlExitUserThread");
	if ((NULL == ntdll_LdrLoadDll) || (NULL == ntdll_RtlCreateUserThread) || (NULL == ntdll_RtlExitThread)) {
		delete [] paramemter_mem_local;
		return Error_GetProcAddress;
	}

	unsigned char tmp_shell_code[shell_code_x64_len];
	memset(tmp_shell_code, 0, shell_code_x64_len);
	memcpy(tmp_shell_code, shell_code_x64, shell_code_x64_len);

	//r9
	memcpy(tmp_shell_code+0x20,&paramemter_mem_addr,sizeof(DWORD64));

	//r8
	DWORD64 ptr = paramemter_mem_addr+sizeof(DWORD64);
	memcpy(tmp_shell_code+0x2a,&ptr,sizeof(PUNICODE_STRING));

	//LdrLoaddll
	memcpy(tmp_shell_code+0x48,&ntdll_LdrLoadDll,sizeof(DWORD64));

	//RtlExitUserThread
	memcpy(tmp_shell_code+0x5e,&ntdll_RtlExitThread,sizeof(DWORD64));
	size_t write_size = 0;
	if (!WriteProcessMemory64(hProcess,paramemter_mem_addr,paramemter_mem_local,paramemter_size,NULL) ||
		!WriteProcessMemory64(hProcess,shell_code_addr,tmp_shell_code,shell_code_x64_len,NULL)) {
			delete [] paramemter_mem_local;
			return Error_WriteProcessMemory;
	}
	DWORD64 hRemoteThread = 0;
	struct {
		DWORD64 UniqueProcess;
		DWORD64 UniqueThread;
	} client_id;
	int a = X64Call(ntdll_RtlCreateUserThread,10,
		(DWORD64)hProcess,					// ProcessHandle
		(DWORD64)NULL,                      // SecurityDescriptor
		(DWORD64)FALSE,                     // CreateSuspended
		(DWORD64)0,                         // StackZeroBits
		(DWORD64)NULL,                      // StackReserved
		(DWORD64)NULL,                      // StackCommit
		shell_code_addr,					// StartAddress
		(DWORD64)NULL,                      // StartParameter
		(DWORD64)&hRemoteThread,            // ThreadHandle
		(DWORD64)&client_id);               // ClientID)
	if ((NULL == hRemoteThread) || (INVALID_HANDLE_VALUE == (HANDLE)hRemoteThread)) {
		delete [] paramemter_mem_local;
		return Error_CreateRemoteThread;
	}
	WaitForSingleObject((HANDLE)hRemoteThread,INFINITE);

	delete [] paramemter_mem_local;
	return OK;
}

BOOL Wow64Injectx64(HANDLE hProcess, LPCTSTR lpDllFilePath) {
	if ((!lpDllFilePath) || (!::PathFileExists(lpDllFilePath))) {
		return FALSE;
	}

	if ((NULL == hProcess) || (INVALID_HANDLE_VALUE == hProcess)) {
		return FALSE;
	}

	InjectResult inject_res = Wow64Injectx64Ex(hProcess, lpDllFilePath);
	return (OK == inject_res);
}

#endif

