# DLL-Obfuscation-V2

This Project is the Second version of DLL-Obfuscation that i did before.

it work by intercepting the excution path of LoadLibraryA by setting a HardWare Breakpoint on ZwMapViewOfSection, then decrypt the code section of the Dll after mapping it to memory as Image.

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