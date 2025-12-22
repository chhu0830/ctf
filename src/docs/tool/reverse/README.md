# Reverse

## File Format

- `$ file`

### ELF
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

### PE
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

### Stego
- binwalk 
- polyfile
    - `polyfile <file>.pdf --html <file>.html`

- [file signature](https://filesignatures.net/)

    > `47 49 46 38` GIF8
    >
    > `89 50 4e 47` .PNG

- [Stego](https://0xrick.github.io/lists/stego/)
    - zsteg
    - stegsolve.jar

- `qpdf --qdf --object-streams=disable <infile> <outfile>`


## Static Analysis

### Demangler
- `$ c++filt`

### Decompiler
- [Decompiler Explorer Online](https://dogbolt.org/)
- [Compiler Explorer Online](https://godbolt.org/)
- jad
- uncompyle6
- [dnSpy](https://github.com/dnSpy/dnSpy) (.Net Framwork)
- Telerik/JustAssembly
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

## Dynamic Analysis

### Running Environ
- x86 binary on x64 OS
    - `$ sudo apt install mingw-w64`
        - `/usr/x86_64-w64-mingw32/include`
        - `/usr/i686-w64-mingw32/include`

### Acativity Monitoring
- Program Instrumentation
    - `$ patchelf --set-interpreter ./libc/ld-linux.so.2 --set-rpath ./libc/ <bin>`
    - `$ env LD_PRELOAD=<lib> <bin>`
    - pintool

- System Instrumentation
    - sandboxie
    - regsnap
    - regshot
    - [Microsoft Research Detours Package](https://github.com/microsoft/Detours)
    - Process Monitor (SysinternalsSuite)
    - strace / ltrace

### Debugger
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



## Exploit
- pwntools
- one\_gadget
- angr
