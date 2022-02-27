# BokuLoader - Cobalt Strike Reflective Loader
Cobalt Strike [User-Defined Reflective Loader](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/malleable-c2-extend_user-defined-rdll.htm) written in Assembly & C for advanced evasion capabilities.

### Project Contributors: [Bobby Cooke](https://twitter.com/0xBoku) & [Santiago Pecin](https://twitter.com/s4ntiago_p)

![](/images/top2.png)

+ This project is based on [Stephen Fewer's](https://twitter.com/stephenfewer) incredible Reflective Loader project: 
  + https://github.com/stephenfewer/ReflectiveDLLInjection
+ Initially created while working through Renz0h's Reflective DLL videos from the [Sektor7 Malware Developer Intermediate (MDI) Course](https://institute.sektor7.net/courses/rto-maldev-intermediate/) 

## Features
| Feature | Description |
|:-------:|:------------|
| BEACON_RDLL_SIZE 100K | BokuLoader uses the increased reserved size in Beacon for a larger User Defined Reflective Loader. This increases the initial beacon size to 100kb (5kb default). BokuLoader will work out of the box when generating raw unstaged shellcode. BokuLoader will not work out of the box with the default Cobalt Strike Artifact kit. [A custom artifact kit must be loaded](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/malleable-c2-extend_user-defined-rdll.htm), which increases the `stagesize` to 412256 on `build.sh` in the artifact kit. |
| x86 Support | [@Santiago Pecin](https://twitter.com/s4ntiago_p) - New 32bit loader with WOW64 support, 32bit Halos&HellsGate, code optimizations & bug fixes! |
| Direct Syscalls | HellsGate & HalosGate direct syscaller, replaced allot of ASM stubs, code refactor, and ~500 bytes smaller. Credit to @SEKTOR7net the jedi HalosGate creator & @smelly__vx & @am0nsec Creators/Publishers of the Hells Gate technique! |
| AMSI & ETW bypasses | AMSI & ETW bypasses baked into reflective loader. Can disable by commenting #define BYPASS line when compiling. Credit to @mariuszbit for the awesome idea. Credit to @\_xpn\_ + @offsectraining + @ajpc500 for their research and code |
| [Custom xGetProcAddress](https://github.com/boku7/BokuLoader/blob/main/BokuLoader.x64.c#L535) | Resolve APIs natively, without using the `GetProcAddres()` WINAPI |
| [Malleable PE](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/malleable-c2-extend_pe-memory-indicators.htm#_Toc65482854) Support | [@Santiago Pecin](https://twitter.com/s4ntiago_p) - Added support for loader options directly from the configured Cobalt Strike Malleable C2 profile. Options supported are `stomppe`,`obfuscate`,`userwx`, and `sleep_mask` |
| FREE_HEADERS | Loader will not copy headers over to beacon. Decommits the first memory page which would normally hold the headers. | 
| STOMP_HEADERS | If `stomppe: true` in Cobalt Strike Malleable Profile is set, then the loader will stomp out the PE header | 
| `userwx: false` | The Reflective loader writes beacon with Read & Write permissions and after resolving Beacons Import Table & Relocations, changes the .TEXT code section of Beacon to Read & Execute permissions | 

## Usage
1. Start the Cobalt Strike Team Server.
2. Connect to the CS Team Server using the CS GUI client.
3. Ensure mingw GCC is installed. (MacOS & Linux supported)
4. If generating RAW payloads, skip this step. This step is for native artifact support.
  + Download the Cobalt Strike Artifact Kit.
  + Set the stagesize to 412256 within `build.sh` of the artifact kit.
  ![](/images/changeStagesize.png)
  + Build the Artifacts.
  + Load the Artifact Aggressor script via the Script Manager within the CS GUI client.
  ![](/images/loadArtifact.png)
5. Import the `BokuLoader.cna` Aggressor script via the Script Manager.
  ![](/images/loadRdllScriptMenu.png)
6. Generate a beacon payload (`Attacks` -> `Packages` -> `Windows Executable (S)`)
  ![](/images/CreateBeaconStageless.png)

## Credits / References
### Reflective Loader
+ https://github.com/stephenfewer/ReflectiveDLLInjection
+ 100% recommend these videos if you're interested in Reflective DLL:  
  + [Dancing with Import Address Table (IAT) - Sektor 7 MDI Course](https://institute.sektor7.net/courses/rto-maldev-intermediate/463262-pe-madness/1435207-dancing-with-iat)
  + [Walking through Export Address Table - Sektor 7 MDI Course](https://institute.sektor7.net/courses/rto-maldev-intermediate/463262-pe-madness/1435189-walking-through-export-address-table)
  + [Reflective Injection Explained - Sektor 7 MDI Course](https://institute.sektor7.net/courses/rto-maldev-intermediate/463258-reflective-dlls/1435355-reflective-injection-explained)
  + [ReflectiveLoader source review - Sektor 7 MDI Course](https://institute.sektor7.net/courses/rto-maldev-intermediate/463258-reflective-dlls/1435383-reflectiveloader-source-review)
### HalosGate SysCaller
+ Reenz0h from @SEKTOR7net
  + Most of the C techniques I use are from Reenz0h's awesome courses and blogs 
  + Best classes for malware development out there.
  + Creator of the halos gate technique. His work was the motivation for this work.
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
### Cobalt Strike C2 Profile Generator
+ [Tylous's epic SourcePoint project](https://github.com/Tylous/SourcePoint)
