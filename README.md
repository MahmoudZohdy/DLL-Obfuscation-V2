# DLL-Obfuscation-V2

This Project is the Second version of DLL-Obfuscation that i did before, the difference is that in this version the Dll will be loaded normaly like any other Dll on the system (it will be called on Process\Thread Attach and detach) the First Version uses Reflective DLL injection to load the Encrypted Dll.

it work by intercepting the excution path of LoadLibraryA by setting a Hardware Breakpoint on ZwMapViewOfSection, then decrypt the code section of the Dll after mapping it to memory as Image.

# How to use
```
DLL-Obfuscation-V2.exe <Operation Type>  <Clean Dll Path> <Obfuscated Dll Path>
Operation Type:
    1 Encrypt the DLL
    2 Load Encrypted Dll
DLL-Obfuscation-V2.exe 1 TestDll.dll ObfuscatedTestDll.dll
DLL-Obfuscation-V2.exe 2 ObfuscatedTestDll.dll
```

# Note:
the Dll should be on fixed address (No relocation) as this will courupte the decryption of the code section.

the decryption is simple XOR with 0xAB

# Demo

![Clean](https://github.com/MahmoudZohdy/DLL-Obfuscation-V2/blob/main/images/Clean.PNG)

Obfuscated Version
![Obfuscated](https://github.com/MahmoudZohdy/DLL-Obfuscation-V2/blob/main/images/Encrypted.PNG)