# BokuLoader - Cobalt Strike Reflective Loader
A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate, integrate, and enhance Cobalt Strike's evasion features!

## Current Goal:
+ Integrate with CS to handle malleable PE C2 profile options, or recreate the malleable PE options within BokuLoader.

### Contributors: [Bobby Cooke @0xBoku](https://twitter.com/0xBoku) & [Santiago Pecin @s4ntiago_p](https://twitter.com/s4ntiago_p) 

## Features
+ Supports all allocator methods via C2 profile 
  - `set MapViewOfFile` uses `kernel32.CreateFileMappingA` & `kernel32.MapViewOfFile` 
  - `set VirtualAlloc` uses direct syscall to `NtAllocateVirtualMemory`
  - `set HeapAlloc` uses `kernel32.GetProcessHeap` and `ntdll.RtlAllocateHeap`
  - All memory protection changes are done via direct syscall to `NtProtectVirtualMemory`
+ Supports DLL Module stomping via C2 profile with `set module_x64`
  - Uses same IOCs as CS: 
    - `Kernel32.LoadLibraryEx`
    - Does not resolve addresses in LDR PEB entry as detailed by [MDSec here](https://www.mdsec.co.uk/2022/07/part-2-how-i-met-your-beacon-cobalt-strike/)
  - [Same DLL stomping requirements set by CS implementation apply](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/malleable-c2-extend_pe-memory-indicators.htm)
+ Supports `obfuscate "true"` with custom UDRL Aggressor script implementation.
+ Supports sleepmask kit Ekko implementation
+ Direct NT Syscalls via HellsGate & HalosGate
+ PE Header Obfuscation
+ PE String Replacement
+ NOHEADERCOPY - Loader will not copy headers raw beacon DLL to virtual beacon DLL. First `0x1000` bytes will be nulls.
+ NoRWX -  The Reflective loader writes beacon with Read & Write permissions and after resolving Beacons Import Table & Relocations, changes the .TEXT code section of Beacon to Read & Execute permissions 
+ XGetProcAddress for resolving symbols
+ 100k UDRL Size
+ Caesar Cipher for string obfuscation
+ Prepend ASM Instructions
+ Supports Malleable C2 profile option `cleanup "true"`
+ Zero out the export directory.
+ `set entry_point` supported.

## Test
+ (2/22/23) All 4 allocator methods tested with [threatexpress/malleable-c2/master/jquery-c2.4.7.profile](https://raw.githubusercontent.com/threatexpress/malleable-c2/master/jquery-c2.4.7.profile)

## Project Origins
+ Based on Stephen Fewer's incredible Reflective Loader project: 
  + https://github.com/stephenfewer/ReflectiveDLLInjection
+ Initially created while working through Renz0h's Reflective DLL videos from the [Sektor7 Malware Developer Intermediate (MDI) Course](https://institute.sektor7.net/courses/rto-maldev-intermediate/) 

## Usage
1. Compile the BokuLoader Object file with `make`
2. Start your Cobalt Strike Team Server
3. Within Cobalt Strike, import the `BokuLoader.cna` Aggressor script
4. Generate the x64 beacon (Attacks -> Packages -> Windows Executable (S))
5. Use the `Script Console` to ensure BokuLoader was implemented in the beacon build

+ Does not support x86 option. The x86 bin is the original Reflective Loader object file.  
+ Generating `RAW` beacons works out of the box. When using the Artifact Kit for the beacon loader, the `stagesize` variable must be larger than the default.
  + See the [Cobalt Strike User-Defined Reflective Loader documenation](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/malleable-c2-extend_user-defined-rdll.htm) for additional information

## Detection Guidance
+ BokuLoader changes some commonly detected strings to new hardcoded values. These strings can be used to signature BokuLoader:

|Original Cobalt Strike String|BokuLoader Cobalt Strike String|
|------------------------------|---------------------------------|
|ReflectiveLoader|djoiqnfkjlnslfmn|
|Microsoft Base Cryptographic Provider v1.0|12367321236742382543232341241261363163151d|
|(admin)|(tomin)|
|beacon|bacons|
+ BokuLoader calls the following NT systemcalls to setup the loaded executable beacon memory: `NtAllocateVirtualMemory`, `NtProtectVirtualMemory`, `NtFreeVirtualMemory`
  + These are called directly from the BokuLoader executable memory. These system calls are not backed by NTDLL memory.
  + Setting userland hooks in `ntdll.dll` will not detect these systemcalls.
  + It may be possible to register kernelcallbacks using a kernel driver to monitor for the above system calls and detect their usage when they are not called from `ntdll.dll`.
  + The BokuLoader itself will contain the `mov eax, r11d; syscall; ret` assembly instructions within its executable memory.
+ The loaded beacon memory is hardcoded as a `Private: Commit` memory region and is `292KB`.
  + The memory section will be loaded at a `+0x1000` offset. This is due to the first 0x1000 bytes of the memory being deallocated within BokuLoader.
+ The BokuLoader source code is provided within the repository and can be used to create memory signatures.
+ If you have additional detection guidance, please feel free to contribute by submitting a pull request. 
  

## Credits / References
### Reflective Loader
+ https://github.com/stephenfewer/ReflectiveDLLInjection
+ Checkout these videos if you're interested in Reflective DLL:  
  + [Dancing with Import Address Table (IAT) - Sektor 7 MDI Course](https://institute.sektor7.net/courses/rto-maldev-intermediate/463262-pe-madness/1435207-dancing-with-iat)
  + [Walking through Export Address Table - Sektor 7 MDI Course](https://institute.sektor7.net/courses/rto-maldev-intermediate/463262-pe-madness/1435189-walking-through-export-address-table)
  + [Reflective Injection Explained - Sektor 7 MDI Course](https://institute.sektor7.net/courses/rto-maldev-intermediate/463258-reflective-dlls/1435355-reflective-injection-explained)
  + [ReflectiveLoader source review - Sektor 7 MDI Course](https://institute.sektor7.net/courses/rto-maldev-intermediate/463258-reflective-dlls/1435383-reflectiveloader-source-review)
+ TitanLdr
+ [AceLdr](https://github.com/kyleavery/AceLdr)
+ [KaynLdr](https://github.com/Cracked5pider/KaynLdr)
### HalosGate SysCaller
+ Reenz0h from @SEKTOR7net
  + Checkout Reenz0h's awesome courses and blogs!
  + Best classes for malware development I have taken.
  + Creator of the halos gate technique. His work was initially the motivation for this work.
  + [Sektor7 HalosGate Blog](https://blog.sektor7.net/#!res/2021/halosgate.md)
### HellsGate Syscaller
+ @smelly__vx & @am0nsec ( Creators/Publishers of the Hells Gate technique )
  + Could not have made my implementation of HellsGate without them :)
  + Awesome work on this method, really enjoyed working through it myself. Thank you!
  + https://github.com/am0nsec/HellsGate 
  + Link to the [Hell's Gate paper: https://vxug.fakedoma.in/papers/VXUG/Exclusive/HellsGate.pdf](https://vxug.fakedoma.in/papers/VXUG/Exclusive/HellsGate.pdf)
### Cobalt Strike User Defined Reflective Loader
+ https://www.cobaltstrike.com/help-user-defined-reflective-loader
### Great Resource for learning Intel ASM
+ [Pentester Academy - SLAE64](https://www.pentesteracademy.com/course?id=7)
### ETW and AMSI Bypass 
+ @mariuszbit - for awesome idea to implement bypasses in reflective loader!
+ [@_XPN_ Hiding Your .NET – ETW](https://www.mdsec.co.uk/2020/03/hiding-your-net-etw/)
+ [ajpc500/BOFs](https://github.com/ajpc500/BOFs/)
+ [Offensive Security OSEP](https://www.offensive-security.com/pen300-osep/)
### Implementing ASM in C Code with GCC
+ https://outflank.nl/blog/2020/12/26/direct-syscalls-in-beacon-object-files/
+ https://www.cs.uaf.edu/2011/fall/cs301/lecture/10_12_asm_c.html
+ http://gcc.gnu.org/onlinedocs/gcc-4.0.2/gcc/Extended-Asm.html#Extended-Asm
### Cobalt Strike C2 Profiles
+ [Tylous's epic SourcePoint project](https://github.com/Tylous/SourcePoint)
+ [threatexpress/malleable-c2/jquery-c2.4.7.profile](https://raw.githubusercontent.com/threatexpress/malleable-c2/master/jquery-c2.4.7.profile)
