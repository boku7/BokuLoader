# BokuLoader - Cobalt Strike Reflective Loader
Cobalt Strike User-Defined Reflective Loader written in Assembly & C for advanced evasion capabilities.

![](/images/top2.png)

+ Based on Stephen Fewer's incredible Reflective Loader project: 
  + https://github.com/stephenfewer/ReflectiveDLLInjection
+ Created while working through Renz0h's Reflective DLL videos from the [Sektor7 Malware Developer Intermediate (MDI) Course](https://institute.sektor7.net/courses/rto-maldev-intermediate/) 

## Versions
+ Different version of this User-Defined Reflective Loader project can be found in the versions folder

| Version | File | Description |
|:-------:|:-----|:------------|
|0.7|BokuLoader-v0_7.c| Updated to work with Cobalt Strike v4.5! |
|0.6|ReflectiveLoader-v0_6.c| NoRWX feature added! The Reflective loader writes beacon with Read & Write permissions and after resolving Beacons Import Table & Relocations, changes the .TEXT code section of Beacon to Read & Execute permissions |
|0.5|ReflectiveLoader-v0_5.c| Added HellsGate & HalosGate direct syscaller, replaced allot of ASM stubs, code refactor, and ~500 bytes smaller. Credit to @SEKTOR7net the jedi HalosGate creator & @smelly__vx & @am0nsec Creators/Publishers of the Hells Gate technique! Credit to @ilove2pwn_ for recommending removing ASM Stubs! Haven't got all of them, but will keep working at it :) |
|0.4|ReflectiveLoader-v0_4.c| AMSI & ETW bypasses baked into reflective loader. Can disable by commenting #define BYPASS line when compiling. Credit to @mariuszbit for the awesome idea. Credit to @\_xpn\_ + @offsectraining + @ajpc500 for their research and code |
|0.3.1|ReflectiveLoader-v0_3_1.c| Changed strings from wchar to char and unpack them to unicode with MMX registers. Fixes linux compilation error discovered by @mariuszbit |
|0.3|ReflectiveLoader-v0_3.c| String obfuscation using new technique. |
|0.2|ReflectiveLoader-v0_2.c| Checks the Loader to see if dependent DLL's already exist to limit times LoadLibrary() is called, custom GetSymbolAddress function to reduce calls to GetProcAddress(), and code refactor. |
|0.1|ReflectiveLoader-v0_1.c| This is the original reflective loader created for this project. It includes the notes within the C file. This initial version was created with research and learning in mind. Little obfuscation and evasion techniques are used in this version.|

## Usage
1. Start your Cobalt Strike Team Server with or without a profile
2. Go to your Cobalt Strike GUI and import the BokuLoader.cna Agressor script.   
![](/images/loadRdllScriptMenu.png)
3. Generate your x64 payload (Attacks -> Packages -> Windows Executable (S))
  + Does not support x86 option. The x86 bin is the original Reflective Loader object file.  
![](/images/CreateBeaconStageless.png)
4. Use the Script Console to make sure that the beacon created successfully with this User-Defined Reflective Loader
  + If successful, the output in the Script Console will look like this:  
![](/images/beaconCreateSuccess.png)

## Build (Only tested from macOS at the moment)
1. Run the compile-x64.sh shell script after installling required dependencies
```bash
# Install brew on macOS if you need it (https://brew.sh/)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
# Install Ming using Brew
brew install mingw-w64
# Clone this Reflective DLL project from this github repo
git clone https://github.com/boku7/BokuLoader.git
# Compile the BokuLoader Object file
cd BokuLoader/
cat compile-x64.sh
x86_64-w64-mingw32-gcc -c BokuLoader.c -o BokuLoader.o -shared -masm=intel
bash compile-x64.sh
```
2. Follow "Usage" instructions

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
