# CDL
Compact Detour Library (C)

# Abstract
CDL is an experimental detours library written in C for x86_64 Linux. It allows
for the interception of C/C++ functions in memory. These functions may be
standalone or PLT (Procedure Linkage Table) calls.

The library currently supports two types of function hooks:
* JMP patch - patches origin function with a JMP to detour
* INT3 patch - places software breakpoint at origin address. Handles control flow to detour.

This project makes use of the [udis86](https://github.com/vmt/udis86)
x86_64 disassembly engine.

# API
```
struct cdl_jmp_patch  cdl_jmp_attach(void **target, void *detour);
struct cdl_swbp_patch cdl_swbp_attach(void **target, void *detour);
void cdl_jmp_detach(struct cdl_jmp_patch *jmp_patch);
void cdl_swbp_detach(struct cdl_swbp_patch *swbp_patch);
void cdl_jmp_dbg(struct cdl_jmp_patch *jmp_patch);
void cdl_swbp_dbg(struct cdl_swbp_patch *swbp_patch);
```
The API is documented in more detail in the corresponding header and source
files.

# Warnings
This project is still in alpha stage.

# Info
**cdl.c** - C source file for CDL. <br>
**cdk.h** - CDL header file to include.

Folders:
* **/tests** - CDL test suite. Run `make all`.

**Project Completion Date: 30/12/2022**
