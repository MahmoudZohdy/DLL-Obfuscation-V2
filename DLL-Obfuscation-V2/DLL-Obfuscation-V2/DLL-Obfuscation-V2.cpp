#include "Utiliti.h"

void PrintUsage() {

	printf("DLL-Obfuscation-V2.exe <Operation Type>  <Clean Dll Path> <Obfuscated Dll Path>\n\n");
	printf("Operation Type:\n 1 Encrypt the DLL\n 2 Load Encrypted Dll\n\n");
	printf("DLL-Obfuscation-V2.exe 1 TestDll.dll ObfuscatedTestDll.dll\n");
	printf("DLL-Obfuscation-V2.exe 2 ObfuscatedTestDll.dll\n");

	return;
}

CHAR CleanDllName[MAX_PATH];
CHAR ObfuscatedDllName[MAX_PATH];

int main(int argc, CHAR* argv[])
{
	if (argc < 2) {
		PrintUsage();
		return 0;
	}
	int type = atoi(argv[1]);
	
	switch (type)
	{
	case 1:
		strcpy(CleanDllName, argv[2]);
		strcpy(ObfuscatedDllName, argv[3]);
		GenerateEncryptedDLL(CleanDllName, ObfuscatedDllName);
		break;

	case 2:

		LoadEncryptedDll(argv[2]);
		strcpy(ObfuscatedDllName, argv[2]);

		break;

	default:
		break;
	}

    return 0;
}
