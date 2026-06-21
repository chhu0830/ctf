# DLL Injection
- [Injecting API Hooking Attack with DLL Injection | S12 - H4CK](https://medium.com/@s12deff/injecting-api-hooking-attack-with-dll-injection-897548af47a8)
- [Malware Technique: DLL Injection | Ricky Severino](https://rickyseverino.medium.com/malware-technique-dll-injection-ffcb960ab2a1)
  ```mermaid
  flowchart

  malproc((malicious process))

  malproc --> GetCurrentProcess --handle--> OpenProcessToken --handle--> AdjustTokenPrivileges
  malproc --SE_DEBUG_NAME--> LookupPrivilegeValue --LUID--> AdjustTokenPrivileges

  malproc --target process name--> CreateToolhelp32Snapshot --pid--> OpenProcess --hProcess--> VirtualAllocEx --lpRemoteMemory--> WriteProcessMemory
  malproc --injected dll path-->GetFullPathName --path--> WriteProcessMemory

  malproc --kernel32.dll--> GetModuleHandle --hKernel32--> GetProcAddress --lpLoadLibrary--> CreateRemoteThread
  OpenProcess --hProcess--> CreateRemoteThread
  VirtualAllocEx --lpRemoteMemory--> CreateRemoteThread --> dll((injected dll))

  AdjustTokenPrivileges -. needed when process owned by another account .-> VirtualAllocEx
  WriteProcessMemory -.-> CreateRemoteThread
  ```
