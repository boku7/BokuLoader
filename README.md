# Cobalt Strike User-Defined Reflective Loader
Cobalt Strike User-Defined Reflective Loader written in Assembly & C for advanced evasion capabilities.

## Initial Project Goals
+ Learn how reflective loader works.
+ Write my own reflective loader in assembly.
+ Compatible with Cobalt Strike.
+ Cross compile from macOS/Linux.
+ Figure out how to implement inline assembly into a C project.

## Future Project Goals
+ Use the initial project as a template for more advanced evasion techniques leveraging the flexibility of Assembly.
+ Implement Cobalt Strike options such as no RWX, stompPE, module stomping, changing the MZ header, etc.
+ Write a decent Aggressor script.
+ Have different versions of reflective loader to choose from.
+ Implement HellsGate/HalosGate for the initial calls that reflective loader uses (pNtFlushInstructionCache, VirtualAlloc, GetProcAddress, LoadLibraryA, etc).
+ Optimize the assembly code.
+ Some kind of template language overlay that can modify/randomize the registers/methods.

## Credits / References
### Reflective Loader
+ https://github.com/stephenfewer/ReflectiveDLLInjection
+ https://institute.sektor7.net/courses/rto-maldev-intermediate/463258-reflective-dlls
### Cobalt Strike User Defined Reflective Loader
+ https://www.cobaltstrike.com/help-user-defined-reflective-loader
### Implementing ASM in C Code with GCC
+ https://outflank.nl/blog/2020/12/26/direct-syscalls-in-beacon-object-files/
+ https://www.cs.uaf.edu/2011/fall/cs301/lecture/10_12_asm_c.html
+ http://gcc.gnu.org/onlinedocs/gcc-4.0.2/gcc/Extended-Asm.html#Extended-Asm
