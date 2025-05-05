# CloakRAT
CloakRAT is a Remote Access Trojan (RAT) agent developed for Windows (x86-64) and implemented in C/C++.

## Current Features
* **Static & Dynamic (runtime) 2-keys string/raw bytes encryption with per-run XOR keys (`encrypt_strings.py` and `Shared/byte_encryption.*` respectively)**
* **Ephemeral string encryption keys**
* **API call obfuscation via runtime PEB walking** (no static imports; all symbols resolved at runtime)
* **Junk code obfuscation - ASM stubs (`Shared/destruction_code.asm`), junk branches, and misleading operations. (`Shared/junk_codes.h`)**
* **C2 Server - tiny TCPClient with Winsock2, easily swapped for Tor/DNS tunnelling for secured communication**
* **Anti‑debug & anti‑analysis mechanisms (TLS callbacks, NtSetInformationThread, isDebuggerPresent, dummy code)**
* **Static detection evasion from Windows Defender**

## Architecture
```
Injector (notepad.exe by default)
   └─▶ Injects CloakRAT.dll
          ├─ TLS Callback ──▶ early anti‑debug
          └─ DLL (entry) ──▶ StartRAT thread
                 ├─ Anti‑Debug (NtSetInformationThread)
                 ├─ TCPClient  ──▶ C2 server
                 └─ Command Exec (utils::exec)
```

## Future plans
**Note that this is just a "blueprint" for a stealthier injection method and better evasion in general.** 

<details>
<summary>Expand To-Do's</summary>

1. **Bring your own vulnerable driver (BYOVD)** - requesting handles with all PROCESS_ALL_ACCESS permissions through kernel mode, bypassing user space detection, injecting from kernel space directly via the vulnerable driver IOCTL codes - **AdvancedInjector project - under development**
2. Consider putting everything in the TLS callback instead of DllMain and on each thread creation event, check for debugger presence, better stealth, if it will be dynamic tls callback creation then even more stealth. In DLLMain put junk code.
3. Anti debug + Micro VM implementation: when dynamically calling APIs in windows, we can emulate the `call eax` instruction that is performed in the assembly, by registering a VEH (an extension to SEH, that is not frame-based like SEH, but an exception handler to the whole process) for EXCEPTION_BREAKPOINT, then just emulate a `call eax` inside the VEH (basically to perform `call eax` we will place an int 3 in the code that will trigger the VEH) by storing the ret addr and changing RIP to point to the api function addr. [in the wild](https://unit42.paloaltonetworks.com/excel-add-ins-dridex-infection-chain/)
4. Add more Anti debugging checks in the TLS callback (i.e hardware breakpoints, searching for 0xCC opcodes)
5. Change to NT functions instead of Kernel32 (which just invoke the syscall in ntoskrnl.exe) for better stealth
6. Execute syscalls directly instead of letting the NT functions (basically a wrapper for the syscall) do it for us - then we possibly avoid nt functions hooking by AVs (specifically inline Hooking)
7. Obfuscating the runtime XOR key (so it won't be just a 16 byte array in memory)
7. Dynamic TLS callbacks (with obfuscating the new tls callback address)- initiate the first tls callback which will be written to the TLS directory at build time by the linker, and when the loader calls the callback, modify the TLS directory in the PE accordingly and viola, we have a new tls callback that was added at runtime and the loader will just continue to the next callback in the tls addresses table and execute the callback (because it doesn't initially check for the number of callbacks). [in the wild](https://cloud.google.com/blog/topics/threat-intelligence/newly-observed-ursnif-variant-employs-malicious-tls-callback-technique-achieve-process-injection/)
8. In the TLS Callback, instead of segfaulting intentionally (too obvious), try overwriting code in junk functions (by changing the memory region of the .text segment at the specific addresses of the functions, overwrite them, then immediately change the page permissions back - use VirtualProtectEx), to make the program crash at some point anyway in the code, because it will be full of junk code to avoid signature detection. also, overwrite global sensitive variables such as the IP and PORT of the C2 server

</details>

## Prerequisites
* Visual Studio 2022 (v143 toolset)
* Windows SDK 10.0+

## Configuration
* `encrypt_strings.py` - generates `Shared/encrypted_strings_autogen.h` (see python script)
* C2 server - edit `str_ip` in `encrypt_strings.py` and the hard-coded port in `CloakRAT.cpp`

## Contributing
If you have something to add, you are welcome to open a pull request for it or for general documentation and I'll go over it.

## Disclaimer
**CloakRAT is for research purposes only.** I'm not responsible for any harm or legal consequences resulting from unauthorized or malicious use.
