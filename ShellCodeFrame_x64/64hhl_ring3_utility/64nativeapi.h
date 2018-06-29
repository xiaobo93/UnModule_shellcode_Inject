

#pragma  once
#include <stdarg.h>
//#include <winbase.h>
#include <windows.h>
#include <windef.h>
#include <Tlhelp32.h>

#define STATUS_OBJECT_NAME_INVALID       ((NTSTATUS)0xC0000033L)
#define STATUS_NOT_SUPPORTED             ((NTSTATUS)0xC00000BBL)
//add by SevenCat
#ifndef STATUS_INVALID_PARAMETER
#define STATUS_INVALID_PARAMETER         ((NTSTATUS)0xC000000DL)
#endif  /* STATUS_INVALID_PARAMETER */

#define STATUS_INSUFFICIENT_RESOURCES    ((NTSTATUS)0xC000009AL)     // ntsubauth

#define STATUS_UNSUCCESSFUL              ((NTSTATUS)0xC0000001L)
#define STATUS_NOT_IMPLEMENTED           ((NTSTATUS)0xC0000002L)
#define STATUS_INVALID_INFO_CLASS        ((NTSTATUS)0xC0000003L)    // ntsubauth
#define STATUS_INFO_LENGTH_MISMATCH      ((NTSTATUS)0xC0000004L)
//#define STATUS_ACCESS_VIOLATION          ((NTSTATUS)0xC0000005L)    // winnt
//#define STATUS_IN_PAGE_ERROR             ((NTSTATUS)0xC0000006L)    // winnt
#define STATUS_PAGEFILE_QUOTA            ((NTSTATUS)0xC0000007L)
//#define STATUS_INVALID_HANDLE            ((NTSTATUS)0xC0000008L)    // winnt
#define STATUS_BAD_INITIAL_STACK         ((NTSTATUS)0xC0000009L)
#define STATUS_BAD_INITIAL_PC            ((NTSTATUS)0xC000000AL)
#define STATUS_INVALID_CID               ((NTSTATUS)0xC000000BL)
#define STATUS_TIMER_NOT_CANCELED        ((NTSTATUS)0xC000000CL)
//#define STATUS_INVALID_PARAMETER         ((NTSTATUS)0xC000000DL)
#define STATUS_NO_SUCH_DEVICE            ((NTSTATUS)0xC000000EL)
#define STATUS_NO_SUCH_FILE              ((NTSTATUS)0xC000000FL)

#ifndef NT_SUCCESS
#define NT_SUCCESS(x) ((x)>=0)
#define STATUS_SUCCESS ((NTSTATUS)0)
#endif




#define FILE_SUPERSEDE                  0x00000000
#define FILE_OPEN                       0x00000001
#define FILE_CREATE                     0x00000002
#define FILE_OPEN_IF                    0x00000003
#define FILE_OVERWRITE                  0x00000004
#define FILE_OVERWRITE_IF               0x00000005
#define FILE_MAXIMUM_DISPOSITION        0x00000005


#define OBJ_INHERIT             0x00000002L
#define OBJ_PERMANENT           0x00000010L
#define OBJ_EXCLUSIVE           0x00000020L
#define OBJ_CASE_INSENSITIVE    0x00000040L
#define OBJ_OPENIF              0x00000080L
#define OBJ_OPENLINK            0x00000100L
#define OBJ_KERNEL_HANDLE       0x00000200L
#define OBJ_FORCE_ACCESS_CHECK  0x00000400L
#define OBJ_VALID_ATTRIBUTES    0x000007F2L

typedef LONG NTSTATUS;

typedef enum _POOL_TYPE {
	NonPagedPool,
	PagedPool,
	NonPagedPoolMustSucceed,
	DontUseThisType,
	NonPagedPoolCacheAligned,
	PagedPoolCacheAligned,
	NonPagedPoolCacheAlignedMustS,
	MaxPoolType,

	//
	// Note these per session types are carefully chosen so that the appropriate
	// masking still applies as well as MaxPoolType above.
	//

	NonPagedPoolSession = 32,
	PagedPoolSession = NonPagedPoolSession + 1,
	NonPagedPoolMustSucceedSession = PagedPoolSession + 1,
	DontUseThisTypeSession = NonPagedPoolMustSucceedSession + 1,
	NonPagedPoolCacheAlignedSession = DontUseThisTypeSession + 1,
	PagedPoolCacheAlignedSession = NonPagedPoolCacheAlignedSession + 1,
	NonPagedPoolCacheAlignedMustSSession = PagedPoolCacheAlignedSession + 1,
} POOL_TYPE;

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemInformationClassMin = 0,
	SystemBasicInformation = 0,
	SystemProcessorInformation = 1,
	SystemPerformanceInformation = 2,
	SystemTimeOfDayInformation = 3,
	SystemPathInformation = 4,
	SystemNotImplemented1 = 4,
	SystemProcessInformation = 5,
	SystemProcessesAndThreadsInformation = 5,
	SystemCallCountInfoInformation = 6,
	SystemCallCounts = 6,
	SystemDeviceInformation = 7,
	SystemConfigurationInformation = 7,
	SystemProcessorPerformanceInformation = 8,
	SystemProcessorTimes = 8,
	SystemFlagsInformation = 9,
	SystemGlobalFlag = 9,
	SystemCallTimeInformation = 10,
	SystemNotImplemented2 = 10,
	SystemModuleInformation = 11,
	SystemLocksInformation = 12,
	SystemLockInformation = 12,
	SystemStackTraceInformation = 13,
	SystemNotImplemented3 = 13,
	SystemPagedPoolInformation = 14,
	SystemNotImplemented4 = 14,
	SystemNonPagedPoolInformation = 15,
	SystemNotImplemented5 = 15,
	SystemHandleInformation = 16,
	SystemObjectInformation = 17,
	SystemPageFileInformation = 18,
	SystemPagefileInformation = 18,
	SystemVdmInstemulInformation = 19,
	SystemInstructionEmulationCounts = 19,
	SystemVdmBopInformation = 20,
	SystemInvalidInfoClass1 = 20,	
	SystemFileCacheInformation = 21,
	SystemCacheInformation = 21,
	SystemPoolTagInformation = 22,
	SystemInterruptInformation = 23,
	SystemProcessorStatistics = 23,
	SystemDpcBehaviourInformation = 24,
	SystemDpcInformation = 24,
	SystemFullMemoryInformation = 25,
	SystemNotImplemented6 = 25,
	SystemLoadImage = 26,
	SystemUnloadImage = 27,
	SystemTimeAdjustmentInformation = 28,
	SystemTimeAdjustment = 28,
	SystemSummaryMemoryInformation = 29,
	SystemNotImplemented7 = 29,
	SystemNextEventIdInformation = 30,
	SystemNotImplemented8 = 30,
	SystemEventIdsInformation = 31,
	SystemNotImplemented9 = 31,
	SystemCrashDumpInformation = 32,
	SystemExceptionInformation = 33,
	SystemCrashDumpStateInformation = 34,
	SystemKernelDebuggerInformation = 35,
	SystemContextSwitchInformation = 36,
	SystemRegistryQuotaInformation = 37,
	SystemLoadAndCallImage = 38,
	SystemPrioritySeparation = 39,
	SystemPlugPlayBusInformation = 40,
	SystemNotImplemented10 = 40,
	SystemDockInformation = 41,
	SystemNotImplemented11 = 41,
	/* SystemPowerInformation = 42, Conflicts with POWER_INFORMATION_LEVEL 1 */
	SystemInvalidInfoClass2 = 42,
	SystemProcessorSpeedInformation = 43,
	SystemInvalidInfoClass3 = 43,
	SystemCurrentTimeZoneInformation = 44,
	SystemTimeZoneInformation = 44,
	SystemLookasideInformation = 45,
	SystemSetTimeSlipEvent = 46,
	SystemCreateSession = 47,
	SystemDeleteSession = 48,
	SystemInvalidInfoClass4 = 49,
	SystemRangeStartInformation = 50,
	SystemVerifierInformation = 51,
	SystemAddVerifier = 52,
	SystemSessionProcessesInformation	= 53,
	SystemInformationClassMax
} SYSTEM_INFORMATION_CLASS;

typedef CHAR *PSZ;
typedef CONST char *PCSZ;

typedef struct _UNICODE_STRING {
	USHORT  Length;
	USHORT  MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _STRING {
	USHORT  Length;
	USHORT  MaximumLength;
	PCHAR  Buffer;
} ANSI_STRING, *PANSI_STRING;


typedef struct _OBJECT_ATTRIBUTES {
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;        // Points to type SECURITY_DESCRIPTOR
	PVOID SecurityQualityOfService;  // Points to type SECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES;
typedef OBJECT_ATTRIBUTES *POBJECT_ATTRIBUTES;
typedef CONST OBJECT_ATTRIBUTES *PCOBJECT_ATTRIBUTES;


typedef struct _IO_STATUS_BLOCK {
	union {
		NTSTATUS Status;
		PVOID Pointer;
	} DUMMYUNIONNAME;

	ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;






#ifndef _WIN64
typedef struct _SYSTEM_MODULE_TABLE_ENTRY_INFO
{
	ULONG Reserved[2];
	PVOID Base;
	ULONG Size;
	ULONG Flags;
	USHORT Index;
	USHORT Unknown;
	USHORT LoadCount;
	USHORT ModuleNameOffset;//此字段代表basename在ImageName中的偏移.比如ImageName中的内容为"\\Windows\\xxx.exe", ModuleNameOffset则为9
	CHAR ImageName[256];
}SYSTEM_MODULE_TABLE_ENTRY_INFO,*PSYSTEM_MODULE_TABLE_ENTRY_INFO;
#else
typedef struct _SYSTEM_MODULE_TABLE_ENTRY_INFO
{
	ULONG_PTR Reserved[2];  //ULONG Reserved[5];	// native 程序这里为什么是5呢 奇怪了 由于对齐的问题 
	PVOID Base;
	ULONG Size;
	ULONG Flags;
	USHORT Index;
	USHORT NameLength;
	USHORT LoadCount;
	USHORT ModuleNameOffset;//此字段代表basename在ImageName中的偏移.比如ImageName中的内容为"\\Windows\\xxx.exe", ModuleNameOffset则为9
	CHAR ImageName[256];
}SYSTEM_MODULE_TABLE_ENTRY_INFO,*PSYSTEM_MODULE_TABLE_ENTRY_INFO;
#endif

typedef struct SYSTEM_MODULE_INFORMATION
{
	ULONG ulNumberOfModules;
	SYSTEM_MODULE_TABLE_ENTRY_INFO smi[1];
}SYSTEM_MODULE_INFORMATION,*PSYSTEM_MODULE_INFORMAT;





//#define FIELD_OFFSET(type,fld)	((LONG)&(((type *)0)->fld))

//typedef int (FAR WINAPI *FARPROC)();



//////kernel32部分的函数开始

typedef FARPROC (WINAPI *TGetProcAddress)(HMODULE, LPCSTR);
typedef HMODULE (WINAPI *TLoadLibraryA)(LPCSTR);
typedef VOID	(WINAPI *TOutputDebugStringA)(LPCSTR);
typedef VOID    (WINAPI *Tprintf)(LPCSTR);
typedef LPVOID (WINAPI *TVirtualAllocEx)(HANDLE hProcess,LPVOID lpAddress,SIZE_T dwSize,DWORD flAllocationType,DWORD flProtect);
typedef HANDLE (WINAPI *TGetCurrentProcess)  (void);
typedef HANDLE (WINAPI *TCreateFileA) (LPCSTR lpFileName,DWORD dwDesiredAccess,DWORD dwShareMode,LPSECURITY_ATTRIBUTES lpSecurityAttributes,DWORD dwCreationDisposition,DWORD dwFlagsAndAttributes,HANDLE hTemplateFile);
typedef DWORD  (WINAPI *TGetFileSize) (HANDLE hFile,LPDWORD lpFileSizeHigh);
typedef BOOL   (WINAPI *TReadFile) (HANDLE hFile,LPVOID lpBuffer,DWORD nNumberOfBytesToRead,LPDWORD lpNumberOfBytesRead,LPOVERLAPPED lpOverlapped);
typedef BOOL   (WINAPI *TVirtualFreeEx) (HANDLE hProcess,LPVOID lpAddress,SIZE_T dwSize,DWORD dwFreeType);
typedef HMODULE (WINAPI *TGetModuleHandleA) (LPCTSTR lpModuleName);
typedef BOOL (WINAPI *TVirtualProtectEx)(HANDLE hProcess,LPVOID lpAddress,SIZE_T dwSize,DWORD flNewProtect,PDWORD lpflOldProtect);
typedef LPVOID (WINAPI *TVirtualAlloc) (LPVOID lpAddress,SIZE_T dwSize,DWORD flAllocationType,DWORD flProtect);
typedef BOOL   (WINAPI *TVirtualFree)    (LPVOID lpAddress,SIZE_T dwSize,DWORD dwFreeType);
typedef

NTSTATUS
(WINAPI *TZwQuerySystemInformation)(
									IN SYSTEM_INFORMATION_CLASS  SystemInformationClass,
									IN OUT PVOID  SystemInformation,
									IN ULONG  SystemInformationLength,
									OUT PULONG  ReturnLength  OPTIONAL);
typedef
PVOID
(WINAPI *TRtlAllocateHeap)( 
						   IN PVOID  HeapHandle,
						   IN ULONG  Flags,
						   IN SIZE_T  Size
						   ); 
typedef
BOOLEAN
(WINAPI *TRtlFreeHeap)( 
					   IN PVOID  HeapHandle,
					   IN ULONG  Flags,
					   IN PVOID  HeapBase
					   ); 

typedef
NTSTATUS
(WINAPI *TRtlGetVersion)(IN OUT PRTL_OSVERSIONINFOW  lpVersionInformation);

typedef
VOID 
(WINAPI *TRtlFreeUnicodeString)(IN PUNICODE_STRING  UnicodeString);

typedef
VOID 
(WINAPI *TRtlZeroMemory)(IN VOID UNALIGNED  *Destination,IN SIZE_T  Length);

typedef
VOID 
(WINAPI *TRtlCopyMemory)(
						 IN VOID UNALIGNED  *Destination,
						 IN CONST VOID UNALIGNED  *Source,
						 IN SIZE_T  Length
						 );
typedef
VOID 
(WINAPI *TCopyMemory)(
					  IN VOID UNALIGNED  *Destination,
					  IN CONST VOID UNALIGNED  *Source,
					  IN SIZE_T  Length
					  );
typedef
VOID 
(WINAPI *TRtlInitAnsiString)(
							 IN OUT PANSI_STRING  DestinationString,
							 IN PCSZ  SourceString
							 );
typedef
NTSTATUS 
(WINAPI *TRtlAnsiStringToUnicodeString)(
										IN OUT PUNICODE_STRING  DestinationString,
										IN PANSI_STRING  SourceString,
										IN BOOLEAN  AllocateDestinationString
										);

typedef
NTSTATUS  
(WINAPI *TNtCreateFile)(
						OUT PHANDLE  FileHandle,
						IN ACCESS_MASK  DesiredAccess,
						IN POBJECT_ATTRIBUTES  ObjectAttributes,
						OUT PIO_STATUS_BLOCK  IoStatusBlock,
						IN PLARGE_INTEGER  AllocationSize  OPTIONAL,
						IN ULONG  FileAttributes,
						IN ULONG  ShareAccess,
						IN ULONG  CreateDisposition,
						IN ULONG  CreateOptions,
						IN PVOID  EaBuffer  OPTIONAL,
						IN ULONG  EaLength
						);
typedef
DWORD 
(WINAPI *TGetFileSize)(
					   __in          HANDLE hFile,
					   __out         LPDWORD lpFileSizeHigh
					   );
typedef
HANDLE
(WINAPI *TCreateFileMappingA)(
							  __in          HANDLE hFile,
							  __in          LPSECURITY_ATTRIBUTES lpAttributes,
							  __in          DWORD flProtect,
							  __in          DWORD dwMaximumSizeHigh,
							  __in          DWORD dwMaximumSizeLow,
							  __in          LPCSTR lpName
							  );
typedef
LPVOID
(WINAPI *TMapViewOfFile)(
						 __in          HANDLE hFileMappingObject,
						 __in          DWORD dwDesiredAccess,
						 __in          DWORD dwFileOffsetHigh,
						 __in          DWORD dwFileOffsetLow,
						 __in          SIZE_T dwNumberOfBytesToMap
						 );
typedef
BOOL 
(WINAPI *TUnmapViewOfFile)(
						   __in          LPCVOID lpBaseAddress
						   );
typedef
BOOL 
(WINAPI *TCloseHandle)(
					   __in          HANDLE hObject
					   );

typedef
HANDLE 
(WINAPI *TGetProcessHeap)(void);

typedef
LPVOID 
(WINAPI *THeapAlloc)(
					 __in          HANDLE hHeap,
					 __in          DWORD dwFlags,
					 __in          SIZE_T dwBytes
					 );
typedef	
BOOL 
(WINAPI *THeapFree)(
					__in          HANDLE hHeap,
					__in          DWORD dwFlags,
					__in          LPVOID lpMem
					);

typedef
PVOID
(WINAPI *TRtlImageDirectoryEntryToData) (
	PVOID BaseAddress,
	BOOLEAN MappedAsImage,
	USHORT Directory,
	PULONG Size);

typedef
UINT 
(WINAPI *TGetSystemDirectoryA)(
							   __out         LPSTR lpBuffer,
							   __in          UINT uSize
							   );
typedef
HRSRC 
(WINAPI *TFindResourceA)(	HMODULE hModule,
						 LPCTSTR lpName,
						 LPCTSTR lpType
						 );
typedef
HGLOBAL 
(WINAPI *TLoadResource)(   HMODULE hModule,
						HRSRC hResInfo
						);
typedef
LPVOID 
(WINAPI *TLockResource)(    HGLOBAL hResData
						);
typedef
DWORD 
(WINAPI *TSizeofResource)(   HMODULE hModule,
						  HRSRC hResInfo
						  );
typedef
HGLOBAL 
(WINAPI *TGlobalFree)(
					  __in          HGLOBAL hMem
					  );
typedef
BOOL 
(WINAPI *TVirtualProtect)(
						  __in          LPVOID lpAddress,
						  __in          SIZE_T dwSize,
						  __in          DWORD flNewProtect,
						  __out         PDWORD lpflOldProtect
						  );
typedef
HANDLE 
(WINAPI* TOpenProcess)(
						  __in          DWORD dwDesiredAccess,
						  __in          BOOL bInheritHandle,
						  __in          DWORD dwProcessId
						  );
typedef
DWORD 
(WINAPI* TGetProcessImageFileNameA)(
									 __in          HANDLE hProcess,
									 __out         LPSTR lpImageFileName,
									 __in          DWORD nSize
									 );
typedef
DWORD 
(WINAPI* TGetLastError)(void);

typedef
HANDLE 
(WINAPI* TCreateToolhelp32Snapshot)(
									   __in          DWORD dwFlags,
									   __in          DWORD th32ProcessID
									   );


typedef
BOOL 
(WINAPI* TProcess32First)(
						   __in          HANDLE hSnapshot,
						   __in      LPPROCESSENTRY32 lppe
						   );
typedef
BOOL 
(WINAPI* TProcess32Next)(
						  __in          HANDLE hSnapshot,
						  __out         LPPROCESSENTRY32 lppe
						  );

typedef
BOOL 
(WINAPI* TCheckRemoteDebuggerPresent)(
									   __in          HANDLE hProcess,
									   __in      PBOOL pbDebuggerPresent
									   );

typedef
VOID 
(WINAPI* TGetStartupInfoA)(
						   __out         LPSTARTUPINFO lpStartupInfo
						   );


typedef
DWORD 
(WINAPI* TGetTickCount)(void);

typedef
DWORD 
(WINAPI* TGetCurrentProcessId)(void);

typedef
BOOL 
(WINAPI* TIsDebuggerPresent)(void);

typedef
NTSTATUS
(WINAPI *TRtlFormatCurrentUserKeyPath)(
									   OUT PUNICODE_STRING CurrentUserKeyPath
									   );

typedef
LONG 
(WINAPI* TRegCreateKeyExW)	(HKEY hKey,
				LPCWSTR lpSubKey,
				DWORD Reserved,
				LPWSTR lpClass,
				DWORD dwOptions,
				REGSAM samDesired,
				LPSECURITY_ATTRIBUTES lpSecurityAttributes,
				PHKEY phkResult,
				LPDWORD lpdwDisposition);
typedef
LONG 
(WINAPI* TRegSetValueExW) (HKEY hKey,
			   LPCWSTR lpValueName,
			   DWORD Reserved,
			   DWORD dwType,
			   CONST BYTE* lpData,
			   DWORD cbData);
typedef
LONG 
(WINAPI* TRegCloseKey)(
						__in          HKEY hKey
						);

typedef
BOOL 
(WINAPI* TIsWow64Process)(
						   __in          HANDLE hProcess,
						   __out         PBOOL Wow64Process
						   );
typedef
void 
(WINAPI* TGetNativeSystemInfo)(
								__out         LPSYSTEM_INFO lpSystemInfo
								);

typedef
DWORD 
(WINAPI* TGetModuleFileNameA)(
							   __in          HMODULE hModule,
							   __out         LPSTR lpFilename,
							   __in          DWORD nSize
							   );

typedef
DWORD 
(WINAPI* TGetShortPathNameA)(
							  __in          LPSTR lpszLongPath,
							  __out         LPSTR lpszShortPath,
							  __in          DWORD cchBuffer
							  );
typedef
LONG 
(WINAPI* TRegOpenKeyA)(
					   __in          HKEY hKey,
					   __in          LPSTR lpSubKey,
					   __out         PHKEY phkResult
					   );

typedef
LONG 
(WINAPI* TRegOpenKeyExA)(
						 __in          HKEY hKey,
						 __in          LPSTR lpSubKey,
						 DWORD			ulOptions,
						 __in          REGSAM samDesired,
						 __out         PHKEY phkResult
						 );
typedef
LONG 
(WINAPI* TRegSetValueExA)(
						  __in          HKEY hKey,
						  __in          LPSTR lpValueName,
						  DWORD			Reserved,
						  __in          DWORD dwType,
						  __in          const BYTE* lpData,
						  __in          DWORD cbData
						  );
typedef
BOOL 
(WINAPI* TCreateHardLinkA)(
						   __in          LPSTR lpFileName,
						   __in          LPSTR lpExistingFileName,
						   LPSECURITY_ATTRIBUTES lpSecurityAttributes
						   );

typedef
BOOL 
(WINAPI* TCreateHardLinkW)(
						   __in          LPWSTR lpFileName,
						   __in          LPWSTR lpExistingFileName,
						   LPSECURITY_ATTRIBUTES lpSecurityAttributes
						   );
typedef
LONG 
(WINAPI* TRegQueryValueExA)(
							__in          HKEY hKey,
							__in          LPSTR lpValueName,
							LPDWORD		  lpReserved,
							__out         LPDWORD lpType,
							__out         LPBYTE lpData,
							__out		  LPDWORD lpcbData
							);
typedef
LONG 
(WINAPI* TRegQueryValueExW)(
							__in          HKEY hKey,
							__in          LPWSTR lpValueName,
							LPDWORD		  lpReserved,
							__out         LPDWORD lpType,
							__out         LPBYTE lpData,
							__out		  LPDWORD lpcbData
							);
typedef
int 
(WINAPI* TMultiByteToWideChar)(
						UINT CodePage, 
						DWORD dwFlags,         
						LPSTR lpMultiByteStr, 
						int cbMultiByte,       
						LPWSTR lpWideCharStr,  
						int cchWideChar        
						);
typedef
int 
(WINAPI* TWideCharToMultiByte)(
						UINT CodePage, 
						DWORD dwFlags, 
						LPCWSTR lpWideCharStr,
						int cchWideChar, 
						LPSTR lpMultiByteStr, 
						int cbMultiByte,
						LPCSTR lpDefaultChar,    
						LPBOOL lpUsedDefaultChar
						);
typedef
BOOL 
(WINAPI* TCopyFileA)(
					 __in          LPSTR lpExistingFileName,
					 __in          LPSTR lpNewFileName,
					 __in          BOOL bFailIfExists
					 );
typedef
BOOL 
(WINAPI* TCopyFileW)(
					 __in          LPWSTR lpExistingFileName,
					 __in          LPWSTR lpNewFileName,
					 __in          BOOL bFailIfExists
					 );

typedef
UINT 
(WINAPI* TGetSystemDirectoryW)(
							   __out         LPWSTR lpBuffer,
							   __in          UINT uSize
							   );

typedef
VOID 
(WINAPI* TSleep)(
				  __in          DWORD dwMilliseconds
				  );





typedef
DWORD 
(WINAPI* TGetEnvironmentVariableA)(
									__in          LPSTR lpName,
									__out         LPSTR lpBuffer,
									__in          DWORD nSize
									);
typedef
DWORD 
(WINAPI* TGetEnvironmentVariableW)(
								   __in          LPWSTR lpName,
								   __out         LPWSTR lpBuffer,
								   __in          DWORD nSize
								   );
typedef
DWORD 
(WINAPI* TGetPrivateProfileStringA)(
									 __in          LPSTR lpAppName,
									 __in          LPSTR lpKeyName,
									 __in          LPSTR lpDefault,
									 __out         LPSTR lpReturnedString,
									 __in          DWORD nSize,
									 __in          LPSTR lpFileName
									 );
typedef
DWORD 
(WINAPI* TGetPrivateProfileStringW)(
									__in          LPWSTR lpAppName,
									__in          LPWSTR lpKeyName,
									__in          LPWSTR lpDefault,
									__out         LPWSTR lpReturnedString,
									__in          DWORD nSize,
									__in          LPWSTR lpFileName
									);
typedef
BOOL 
(WINAPI* TCreateDirectoryA)(
							__in          LPSTR lpPathName,
							__in          LPSECURITY_ATTRIBUTES lpSecurityAttributes
							);
typedef
BOOL 
(WINAPI* TCreateDirectoryW)(
							__in          LPWSTR lpPathName,
							__in          LPSECURITY_ATTRIBUTES lpSecurityAttributes
							);
typedef
HANDLE 
(WINAPI* TCreateFileW)(
						 __in          LPWSTR lpFileName,
						 __in          DWORD dwDesiredAccess,
						 __in          DWORD dwShareMode,
						 __in          LPSECURITY_ATTRIBUTES lpSecurityAttributes,
						 __in          DWORD dwCreationDisposition,
						 __in          DWORD dwFlagsAndAttributes,
						 __in          HANDLE hTemplateFile
						 );
typedef
BOOL 
(WINAPI* TWriteFile)(
					  __in          HANDLE hFile,
					  __in          LPCVOID lpBuffer,
					  __in          DWORD nNumberOfBytesToWrite,
					  __out         LPDWORD lpNumberOfBytesWritten,
					  __in          LPOVERLAPPED lpOverlapped
					  );
typedef
DWORD 
(WINAPI* TSetFilePointer)(
							__in          HANDLE hFile,
							__in          LONG lDistanceToMove,
							__in_opt  PLONG lpDistanceToMoveHigh,
							__in          DWORD dwMoveMethod
							);
typedef
UINT 
(WINAPI* TWinExec)(
					__in          LPCSTR lpCmdLine,
					__in          UINT uCmdShow
					);
typedef
BOOL 
(WINAPI* TDeleteFileA)(
					   __in          LPSTR lpFileName
					   );
typedef
BOOL 
(WINAPI* TDeleteFileW)(
					   __in          LPWSTR lpFileName
					   );
typedef
BOOL 
(WINAPI* TReadProcessMemory)(
							  __in          HANDLE hProcess,
							  __in          LPCVOID lpBaseAddress,
							  __out         LPVOID lpBuffer,
							  __in          SIZE_T nSize,
							  __out         SIZE_T* lpNumberOfBytesRead
							  );
typedef
BOOL 
(WINAPI* TWriteProcessMemory)(
							   __in          HANDLE hProcess,
							   __in          LPVOID lpBaseAddress,
							   __in          LPCVOID lpBuffer,
							   __in          SIZE_T nSize,
							   __out         SIZE_T* lpNumberOfBytesWritten
							   );

typedef
BOOL 
(WINAPI* TMoveFileA)(
					 __in          LPSTR lpExistingFileName,
					 __in          LPSTR lpNewFileName
					 );
typedef
BOOL 
(WINAPI* TMoveFileW)(
					__in          LPWSTR lpExistingFileName,
					__in          LPWSTR lpNewFileName
					);
typedef
BOOL 
(WINAPI* TMoveFileExA)(
					   __in          LPSTR lpExistingFileName,
					   __in          LPSTR lpNewFileName,
					   __in          DWORD dwFlags
					   );
typedef
BOOL 
(WINAPI* TMoveFileExW)(
					  __in          LPWSTR lpExistingFileName,
					  __in          LPWSTR lpNewFileName,
					  __in          DWORD dwFlags
					  );





















//。。。各种需要的函数声明
