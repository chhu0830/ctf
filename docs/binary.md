# Binary
<!-- toc -->

## Tool

### File Analyzer

#### General
- `$ file`

#### ELF
- readelf

  | Usage | Description |
  |-------|-------------|
  | `$ readelf -S <binary>` | Display the sections' header. |
  | `$ readelf -s <binary>` | Display the symbol table. |

- objdump

  | Usage | Description |
  |-------|-------------|
  | `$ objdump -x <binary>` | Display the contents of all headers. |
  | `$ objdump -R <binary>` | Display the dynamic relocation entries in the file. |
  | `$ objdump -M intel -S <binary>` | Intermix source code with disassembly. |

#### PE
- PE-bear
- PEview
- PE Detective (ExplorerSuite)
- [reshacker](https://www.angusj.com/resourcehacker/)
  - Add, modify or replace resources.
  - Support strings, images, dialogs, menus, VersionInfo and Manifest resources.
- CFF Explorer (ExplorerSuite)
- Signature Explorer (ExplorerSuite)
- 010 editor


### Pack Detector
- PEiD
- DIE (detect it easy)
  - identify shell and other info

### Demangler
- `$ c++filt`

### Decompiler
- [Decompiler Explorer Online](https://dogbolt.org/)
- [Compiler Explorer Online](https://godbolt.org/)
- jad
- uncompyle6
- [dnSpy](https://github.com/dnSpy/dnSpy) (.Net Framwork)
- Telerik/JustAssembly

### Debugger
- IDA pro

  | Usage                                                | Description            |
  |:-----------------------------------------------------|:-----------------------|
  | `<S-F1>`                                             | set variable structure |
  | `<S-F12>`                                            | string list            |
  | `r` / `h`                                            | encode                 |
  | `x`                                                  | xrefs                  |
  | `y`                                                  | type declaration       |
  | `<C-f>`                                              | search                 |
  | `<R>` > `reset pointer type` > `create new struct type` |                        |

  - [IDA Skins](https://github.com/zyantific/IDASkins)
- Ghidra
- Windbg preview
- x64dbg

  | Usage       | Description  |
  |:------------|:-------------|
  | `<Space>`   | modify code  |
  | `<C-p>`     | patch binary |
  | `<R>` > `s` | search       |

- gdb

  | Usage  | Description |
  |:-------|:------------|
  | watch  |             |
  | rwatch |             |
  | awatch |             |
  | x/[N][g,w,h,b]x | |

  - plugins
    - peda
    - gef
    - pwndbg
    - pwngdb
- CheatEngine72

### Running Environ
- x86 binary on x64 OS
  - `$ sudo apt install mingw-w64`
    - `/usr/x86_64-w64-mingw32/include`
    - `/usr/i686-w64-mingw32/include`
- Library
  - `$ patchelf --set-interpreter ./libc/ld-linux.so.2 --set-rpath ./libc/ <bin>`
  - `$ env LD_PRELOAD=<lib> <bin>`
- Behavior
  - sandboxie
  - regsnap
  - regshot
  - [Microsoft Research Detours Package](https://github.com/microsoft/Detours)
  - Process Monitor (SysinternalsSuite)
  - pintool
  - strace / ltrace

### Payload
- pwntools
- one\_gadget
- angr


## Background

### Calling Convention
- Compare

  | Type                             | Platform            | Ret     | Parameters                  | Stack Cleaner | Note                                      | 
  |----------------------------------|---------------------|---------|-----------------------------|---------------|-------------------------------------------|
  | stdcall                          | Win32 API           | eax     | stack                       | callee        |                                           |
  | cdecl                            | Win32 / Linux x86   | eax     | stack                       | caller        |                                           |
  | Microsoft x64 calling convention | Win64               | rax     | rcx,rdx,r8,r9,stack         | caller        |                                           |
  | SysV ABI (C ABI)                 | Linux x86\_64       | rdx:rax | rdi,rsi,rdx,rcx,r8,r9,stack | caller        | called when 16-byte aligned               |
  | syscall                          | Linux x86\_64       | rax     | rdi,rsi,rdx,r10,r8,r9,stack | caller        | rax: syscall number, rcx: rip, r11: flags |
  | int 0x80                         | Linux x86           | eax     | ebx,ecx,edx,esd,edi,ebp     | caller        | eax: syscall number                       |

- Win32 Calling Convention Example
  - stdcall (win32api)

    ```c
    __attribute__((stdcall)) void func(int a, int b, int c) {
      ...
    }
    ```

  - fastcall

    ```c
    __attribute__((fastcall)) void func(int a, int b, int c) {
      ...
    }
    ```

  - thiscall
    > put `this` in `ecx`
    > 
    > used in class member method

    ```
    class human {
      protected:
      string nation;
      public:
      virtual string getNation() {
        return this->nation;
      }
    };
    ```

    ```
    lea edx,[ebp-0x34]
    ...
    mov ecx,edx
    call eax
    ...
    ```

### File Format
- segment register / index in descripter table

#### ELF

#### PE
- Alignment
  - File
    - FileAlignment: 0x200
    - Winchester Disk
  - Process
    - SectionAlignment: 0x1000
    - Page Model
- [PE Format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)

  | Layout  |                               |
  |:--------|:------------------------------|
  | Headers | Dos MZ Header                 |
  |         | DOS Stub                      |
  |         | PE Header (IMAGE\_NT\_HEADER) |
  |         | Section Headers               |
  | Null    |                               |
  | .text   |                               |
  | Null    |                               |
  | .data   |                               |
  | Null    |                               |
  | .rsrc   |                               |
  | Null    |                               |
