# BokuLoader - Cobalt Strike Reflective Loader
Cobalt Strike User-Defined Reflective Loader written in Assembly & C for advanced evasion capabilities.

### Project Contributors: [Bobby Cooke @0xBoku](https://twitter.com/0xBoku) & [Santiago Pecin @s4ntiago_p](https://twitter.com/s4ntiago_p)

## Features
+ Direct NT Syscalls via HellsGate & HalosGate
+ NOHEADERCOPY - Loader will not copy headers over to beacon. Decommits the first memory page which would normally hold the headers
+ NoRWX -  The Reflective loader writes beacon with Read & Write permissions and after resolving Beacons Import Table & Relocations, changes the .TEXT code section of Beacon to Read & Execute permissions 
+ XGetProcAddress for resolving symbols
+ 100k UDRL Size

# Project Origins
+ Based on Stephen Fewer's incredible Reflective Loader project: 
  + https://github.com/stephenfewer/ReflectiveDLLInjection
+ Initially created while working through Renz0h's Reflective DLL videos from the [Sektor7 Malware Developer Intermediate (MDI) Course](https://institute.sektor7.net/courses/rto-maldev-intermediate/) 

## Usage
1. Start your Cobalt Strike Team Server with or without a profile.
2. Unless you only generate RAW payloads, set the stagesize to 412256 on `build.sh` in the artifact kit.
![](/images/changeStagesize.png)
3. Load the `dist-template/artifact.cna` Aggressor script.
![](/images/loadArtifact.png)
4. Go to your Cobalt Strike GUI and import the BokuLoader.cna Aggressor script.
![](/images/loadRdllScriptMenu.png)
5. Generate your x64 payload (Attacks -> Packages -> Windows Executable (S))
  + Does not support x86 option. The x86 bin is the original Reflective Loader object file.  
![](/images/CreateBeaconStageless.png)
6. Use the Script Console to make sure that the beacon created successfully with this User-Defined Reflective Loader
  + If successful, the output in the Script Console will look like this:  
![](/images/beaconCreateSuccess.png)

## Build
1. Run the `make` command after installling required dependencies
```bash
# Install brew on macOS if you need it (https://brew.sh/)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
# Install Ming using Brew
brew install mingw-w64
# Clone this Reflective DLL project from this github repo
git clone https://github.com/boku7/BokuLoader.git
# Compile the BokuLoader Object file
cd BokuLoader/
make
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
