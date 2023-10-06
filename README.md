# BokuLoader : Cobalt Strike Reflective Loader

![](/bokuloader_banner.png)

A proof-of-concept [User-Defined Reflective Loader (UDRL)](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/malleable-c2-extend_user-defined-rdll.htm) which aims to recreate, integrate, and enhance Cobalt Strike's evasion features!

#### Contributors: 
|Contributor|Twitter|Notable Contributions|
|--|--|--|
|Bobby Cooke|[@0xBoku](https://twitter.com/0xBoku)|Project original author and maintainer| 
|Santiago Pecin|[@s4ntiago_p](https://twitter.com/s4ntiago_p)|Reflective Loader major enhancements|
|Chris Spehn|[@ConsciousHacker](https://twitter.com/ConsciousHacker)|Aggressor scripting|
|Joshua Magri|[@passthehashbrwn](https://twitter.com/passthehashbrwn)|IAT hooking|
|Dylan Tran|[@d_tranman](https://twitter.com/d_tranman)|Reflective Call Stack Spoofing|
|James Yeung|[@5cript1diot](https://twitter.com/5cript1diot)|Indirect System Calls|

## UDRL Usage Considerations
The built-in [Cobalt Strike](https://www.cobaltstrike.com/) reflective loader is robust,  handling all [Malleable PE evasion features](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/malleable-c2-extend_pe-memory-indicators.htm) Cobalt Strike has to offer. The major disadvantage to using a custom UDRL is Malleable PE evasion features may or may not be supported out-of-the-box.  

The objective of the public BokuLoader project is to assist red teams in creating their own in-house Cobalt Strike UDRL. The project aims to support all worthwhile CS Malleable PE evasion features. Some evasion features leverage CS integration, others have been recreated completely, and some are unsupported.   

_Before using this project, in any form, you should properly test the evasion features are working as intended. Between the C code and the Aggressor script, compilation with different versions of operating systems, compilers, and Java may  return different results._   

## Evasion Features

### BokuLoader Specific Evasion Features
- Reflective callstack spoofing via synthetic frames.
- Custom ASM/C reflective loader code
- Indirect NT syscalls via HellsGate & HalosGate techniques
  - All memory protection changes for all allocation options are done via indirect syscall to `NtProtectVirtualMemory`
- `obfuscate "true"` with custom UDRL Aggressor script implementation.
- NOHEADERCOPY 
  - Loader will not copy headers raw beacon DLL to virtual beacon DLL. First `0x1000` bytes will be nulls.
- `XGetProcAddress` for resolving symbols
  - Does not use `Kernel32.GetProcAddress`
- `xLoadLibrary` for resolving DLL's base address & DLL Loading
  - For loaded DLLs, gets DLL base address from `TEB->PEB->PEB_LDR_DATA->InMemoryOrderModuleList`
  - Does not use `Kernel32.LoadLibraryA`
- Caesar Cipher for string obfuscation
- 100k UDRL Size
- Import DLL names and import entry name strings are stomped in virtual beacon DLL.

### Supported Malleable PE Evasion Features
|Command|Option(s)|Supported|
|--|--|--|
|`allocator`|HeapAlloc, MapViewOfFile, VirtualAlloc | All supported via BokuLoader implementation|
|`module_x64`| string (DLL Name) | Supported via BokuLoader implementation. [Same DLL stomping requirements as CS implementation apply](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/malleable-c2-extend_pe-memory-indicators.htm)
|`obfuscate`|true/false|HTTP/S beacons supported via BokuLoader implementation. SMB/TCP is currently not supported for obfuscate true. Details in issue. Accepting help if you can fix :) 
|`entry_point`|RVA as decimal number|Supported via BokuLoader implementation
|`cleanup`|true|Supported via CS integration
|`userwx`|true/false|Supported via BokuLoader implementation
|`sleep_mask`|(true/false) or (Sleepmask Kit+true)|Supported. When using default "sleepmask true" (without sleepmask kit) set "userwx true". When using sleepmask kit which supports RX beacon.text memory (`src47/Ekko`) set "sleepmask true" && "userwx false".
|`magic_mz_x64`|4 char string|Supported via CS integration
|`magic_pe`|2 char string|Supported via CS integration
|`transform-x64 prepend`|escaped hex string|`BokuLoader.cna` Aggressor script modification
|`transform-x64 strrep`|string string|`BokuLoader.cna` Aggressor script modification
|`stomppe`|true/false|Unsupported. BokuLoader does not copy beacon DLL headers over. First `0x1000` bytes of virtual beacon DLL are `0x00`
|`checksum`|number|Experimental. `BokuLoader.cna` Aggressor script modification
|`compile_time`|date-time string|Experimental. `BokuLoader.cna` Aggressor script modification
|`image_size_x64`|decimal value|Unsupported
|`name`|string|Experimental. `BokuLoader.cna` Aggressor script modification
|`rich_header`|escaped hex string|Experimental. `BokuLoader.cna` Aggressor script modification
|`stringw`|string|Unsupported
|`string`|string|Unsupported


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
### Hardcoded Strings 
+ BokuLoader changes some commonly detected strings to new hardcoded values. These strings can be used to signature BokuLoader:

|Original Cobalt Strike String|BokuLoader Cobalt Strike String|
|------------------------------|---------------------------------|
|ReflectiveLoader|BokuLoader|
|Microsoft Base Cryptographic Provider v1.0|12367321236742382543232341241261363163151d|
|(admin)|(tomin)|
|beacon|bacons|

### Memory Allocators

#### DLL Module Stomping
- The `Kernel32.LoadLibraryExA` is called to map the DLL from disk
- The 3rd argument to `Kernel32.LoadLibraryExA` is `DONT_RESOLVE_DLL_REFERENCES  (0x00000001)`
  - the system does not call DllMain
- Does not resolve addresses in LDR PEB entry as detailed by [MDSec here](https://www.mdsec.co.uk/2022/07/part-2-how-i-met-your-beacon-cobalt-strike/)
- Detectable by scanning process memory with [pe-sieve](https://github.com/hasherezade/pe-sieve) tool

#### Heap Allocation
- Executable `RX` or `RWX` memory will exist in the heap if sleepmask kit is not used.

#### Mapped Allocator
- The `Kernel32.CreateFileMappingA` & `Kernel32.MapViewOfFile` is called to allocate memory for the virtual beacon DLL.

### Sleepmask Detection
- If sleepmask kit is used, there exists detection methods for this independent memory allocation [as detailed by MDSec here](https://www.mdsec.co.uk/2022/07/part-2-how-i-met-your-beacon-cobalt-strike/)

### Indirect Syscalls
+ BokuLoader calls the following NT systemcalls to setup the loaded executable beacon memory: `NtAllocateVirtualMemory`, `NtProtectVirtualMemory`
+ These are called indirectly from the BokuLoader executable memory.
+ Setting userland hooks in `ntdll.dll` will not detect these systemcalls.
+ It may be possible to register kernelcallbacks using a kernel driver to monitor for the above system calls and detect their usage.
+ The BokuLoader itself will contain the `mov eax, r11d; mov r11, r10; mov r10, rcx; jmp r11` assembly instructions within its executable memory.

### Virtual Beacon DLL Header
- The first `0x1000` bytes of the virtual beacon DLL are zeros.

### Source Code Available
+ The BokuLoader source code is provided within the repository and can be used to create memory signatures.
+ If you have additional detection guidance, please feel free to contribute by submitting a pull request. 
  

## Credits / References
### Reflective Call Stack Spoofing
+ [LoudSunRun: Call stack synthetic frame spoofer with indirect syscalls](https://github.com/susMdT/LoudSunRun)
+ [SilentMoonwalk: PoC Implementation of a fully dynamic call stack spoofer](https://github.com/klezVirus/SilentMoonwalk)
+ [Vulcan Raven: PoC implementation for spoofing arbitrary call stacks when making syscalls](https://github.com/WithSecureLabs/CallStackSpoofer)
+ [CallStackMasker: A PoC implementation for dynamically masking call stacks with timers](https://github.com/Cobalt-Strike/CallStackMasker)
+ [ThreadStackSpoofer: Thread Stack Spoofing PoC](https://github.com/mgeeky/ThreadStackSpoofer)
+ [Behind the Mask: Spoofing Call Stacks Dynamically with Timers](https://www.cobaltstrike.com/blog/behind-the-mask-spoofing-call-stacks-dynamically-with-timers/)
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
### Aggressor Scripting
+ [sinusoid @the_bit_diddler](https://twitter.com/the_bit_diddler) : [returnIntegerFromArray](https://gist.github.com/EspressoCake/612c8fa45e6d608ec0811ef747cf1db7)
### Cobalt Strike User Defined Reflective Loader
+ https://www.cobaltstrike.com/help-user-defined-reflective-loader
### Great Resource for learning Intel ASM
+ [Pentester Academy - SLAE64](https://www.pentesteracademy.com/course?id=7)
### ETW and AMSI Bypass 
+ [@anthemtotheego](https://twitter.com/anthemtotheego) [inline-ExecuteAssembly](https://github.com/xforcered/InlineExecute-Assembly)
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
