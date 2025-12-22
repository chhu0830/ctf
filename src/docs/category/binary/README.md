# Binary

## Calling Convention
- Comparison

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

## Special Section
- .init / .fini

    ```C
    #include <stdio.h>
    __attribute__((constructor(101))) void func1() {
    }

    __attribute__((constructor(102))) void func2() {
    }

    __attribute__((constructor)) void func3() {
    }

    __attribute__((destructor)) void func4() { // Run after main function.
    }

    int main() {
        return 0;
    }
    ```

## File Format
- segment register / index in descripter table

### ELF

### PE
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
