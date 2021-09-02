#pragma once
#pragma warning(disable : 4996)

#include <iostream>
#include <Windows.h>
#include <DbgHelp.h>

#pragma comment(lib, "Dbghelp.lib")

#define KEY 0xAB

#define CALL_FIRST 1  

#if _WIN64			
#define DWORD64 unsigned long long
#else
#define DWORD64 unsigned long
#endif

PIMAGE_NT_HEADERS  GetNTHeaders(DWORD64 dwImageBase) {
	return (PIMAGE_NT_HEADERS)(dwImageBase + ((PIMAGE_DOS_HEADER)dwImageBase)->e_lfanew);
}

PLOADED_IMAGE  GetLoadedImage(DWORD64 dwImageBase)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)dwImageBase;

	PIMAGE_NT_HEADERS pNTHeaders = GetNTHeaders(dwImageBase);
	PLOADED_IMAGE pImage = new LOADED_IMAGE();

	pImage->FileHeader = (PIMAGE_NT_HEADERS)(dwImageBase + pDosHeader->e_lfanew);

	pImage->NumberOfSections = pImage->FileHeader->FileHeader.NumberOfSections;

	pImage->Sections = (PIMAGE_SECTION_HEADER)(dwImageBase + pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));

	return pImage;
}

void EncryptDecryptCodeSection(BYTE* Data, int MemoryType) {
	BOOL bSuccess = FALSE;
	LPVOID lpRemoteLibraryBuffer = NULL;
	LPTHREAD_START_ROUTINE lpReflectiveLoader = NULL;
	HANDLE hThread = NULL;
	DWORD dwReflectiveLoaderOffset = 0;
	DWORD dwThreadId = 0;
	DWORD dwLength;


	PIMAGE_NT_HEADERS pSourceHeaders = GetNTHeaders((DWORD64)Data);

	PLOADED_IMAGE pSourceImage = GetLoadedImage((DWORD64)Data);
	for (DWORD x = 0; x < pSourceImage->NumberOfSections; x++)
	{

		char pSectionName[] = "text";
		char* pch;
		pch = strstr((CHAR*)pSourceImage->Sections[x].Name, "text");
		if (pch == NULL) {
			pch = strstr((CHAR*)pSourceImage->Sections[x].Name, "code");
			if (pch == NULL)
				continue;
		}

		//the data is buffer read from file
		if (MemoryType == 1) {
			for (DWORD i = 0; i < pSourceHeaders->OptionalHeader.SizeOfCode; i++) {
				DWORD64* ByteTohange = (DWORD64*)((DWORD64)Data + (DWORD64)pSourceImage->Sections[x].PointerToRawData + (DWORD64)i);
				*(BYTE*)ByteTohange = *(BYTE*)ByteTohange ^ KEY;

			}
			break;
		}

		//the data is memory mapped for the Dll
		DWORD OldProtection;
		BOOL ret = VirtualProtect((DWORD64*)((DWORD64)Data + (DWORD64)pSourceImage->Sections[x].VirtualAddress), pSourceHeaders->OptionalHeader.SizeOfCode, PAGE_EXECUTE_READWRITE, &OldProtection);
		if (!ret) {
			printf("failed to change protection Error Code %x\n", GetLastError());
			return;
		}

		for (DWORD i = 0; i < pSourceHeaders->OptionalHeader.SizeOfCode; i++) {
			DWORD64* ByteTohange = (DWORD64*)((DWORD64)Data + (DWORD64)pSourceImage->Sections[x].VirtualAddress + (DWORD64)i);
			*(BYTE*)ByteTohange = *(BYTE*)ByteTohange ^ KEY;
		}

		ret = VirtualProtect((DWORD64*)((DWORD64)Data + (DWORD64)pSourceImage->Sections[x].VirtualAddress), pSourceHeaders->OptionalHeader.SizeOfCode, OldProtection, &OldProtection);
		if (!ret) {
			printf("failed to change protection to its original protection Error Code %x\n", GetLastError());
			return;
		}
		break;

	}
}



int Flag = 1;
//Gets Executed when we hit our hardware breakpoint
LONG WINAPI ExceptionHandler(_EXCEPTION_POINTERS* ExceptionInfo)
{
	if (Flag) {

		typedef NTSTATUS(WINAPI* _ZwMapViewOfSection)(
			HANDLE          SectionHandle,
			HANDLE          ProcessHandle,
			PVOID* BaseAddress,
			ULONG_PTR       ZeroBits,
			SIZE_T          CommitSize,
			PLARGE_INTEGER  SectionOffset,
			PSIZE_T         ViewSize,
			DWORD64			InheritDisposition,
			ULONG           AllocationType,
			ULONG           Win32Protect
			);

		NTSTATUS   result = NULL;

#if _WIN64			
		DWORD64* EspValue = (DWORD64*)ExceptionInfo->ContextRecord->Rsp;
#else
		DWORD* EspValue = (DWORD*)ExceptionInfo->ContextRecord->Esp;
#endif

		_ZwMapViewOfSection ZwMapViewOfSectionaddr = (_ZwMapViewOfSection)GetProcAddress(LoadLibraryA("ntdll"), "ZwMapViewOfSection");

		if (!ZwMapViewOfSectionaddr) {
			ExceptionInfo->ContextRecord->Dr0 = 0;
			ExceptionInfo->ContextRecord->Dr7 = 0;

			printf("Faile to get ZwMapViewOfSection address Error Code\n",GetLastError());
			return EXCEPTION_CONTINUE_EXECUTION;
		}


		//Remove HardWare Break Point and Exception
		ExceptionInfo->ContextRecord->Dr0 = 0;
		ExceptionInfo->ContextRecord->Dr7 = 0;
		CONTEXT Context;
		Context.ContextFlags = CONTEXT_DEBUG_REGISTERS;

		RemoveVectoredExceptionHandler(ExceptionHandler);

		GetThreadContext(GetCurrentThread(), &Context);

		Context.Dr0 = 0;
		Context.Dr7 = 0;

		SetThreadContext(GetCurrentThread(), &Context);
		Flag = 0;

		//Search the ZwMapViewOfSection Function For the return address and set instruction pointer to it.
#if _WIN64			
		//0xc3	ret
		for (int i = 0;; i++) {
			if (((BYTE*)ZwMapViewOfSectionaddr)[i] == 0xc3) {
				ExceptionInfo->ContextRecord->Rip = (DWORD64)((BYTE*)ZwMapViewOfSectionaddr + i);
				break;
			}
		}
#else
		// c2 28 00		ret 0x28
		for (int i = 0;; i++) {
			if (((BYTE*)ZwMapViewOfSectionaddr)[i] == 0xc2 && ((BYTE*)ZwMapViewOfSectionaddr)[i + 1] == 0x28 && ((BYTE*)ZwMapViewOfSectionaddr)[i + 2] == 0x00) {
				ExceptionInfo->ContextRecord->Eip = (DWORD64)((BYTE*)ZwMapViewOfSectionaddr + i);
				break;
			}
		}
#endif
		DWORD64* pBaseAddress = NULL;
		SIZE_T size = 0;

#if _WIN64		
		result = ZwMapViewOfSectionaddr((HANDLE)ExceptionInfo->ContextRecord->Rcx, (HANDLE)ExceptionInfo->ContextRecord->Rdx, (PVOID*)ExceptionInfo->ContextRecord->R8, ExceptionInfo->ContextRecord->R9, (SIZE_T)EspValue[5], (PLARGE_INTEGER)EspValue[6], (PSIZE_T)EspValue[7], EspValue[8], EspValue[9], EspValue[10]);

#else		
		result = ZwMapViewOfSectionaddr((HANDLE)EspValue[1], (HANDLE)EspValue[2], (PVOID*)EspValue[3], EspValue[4], EspValue[5], (PLARGE_INTEGER)EspValue[6], (PSIZE_T)EspValue[7], EspValue[8], EspValue[9], EspValue[10]);

#endif
		if (result != 0) {
			printf("ZwMapViewOfSectionaddr failed %x %x\n", result, GetLastError());
			return EXCEPTION_CONTINUE_EXECUTION;
		}


#if _WIN64
		pBaseAddress = (DWORD64*)ExceptionInfo->ContextRecord->R8;

#else
		pBaseAddress = (DWORD64*)(PVOID*)EspValue[3];
#endif
		DWORD64* MapBase = (DWORD64*)(*pBaseAddress);
		DWORD64* Start = MapBase;
		EncryptDecryptCodeSection((BYTE*)Start, 0);

	}

	return EXCEPTION_CONTINUE_EXECUTION;

}


BYTE* ReadDataFromFile(CHAR* FileName) {

	HANDLE hFile = NULL;
	BOOL bResult = FALSE;
	DWORD cbRead = 0;

	hFile = CreateFileA(FileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("Failed To Open Handle To File %S Error Code is 0x%x\n", FileName, GetLastError());
		return NULL;
	}

	int FileSize = GetFileSize(hFile, 0);
	if (FileSize == INVALID_FILE_SIZE) {
		printf("Failed To get File size Error Code is 0x%x\n", GetLastError());
		return NULL;
	}

	BYTE* FileContents = new BYTE[FileSize];
	ZeroMemory(FileContents, FileSize);

	bResult = ReadFile(hFile, FileContents, FileSize, &cbRead, NULL);
	if (bResult == FALSE) {
		printf("Failed To Read File Data Error Code is 0x%x\n", GetLastError());
		return NULL;
	}

	CloseHandle(hFile);
	return FileContents;
}


DWORD GenerateEncryptedDLL(CHAR* FileName, CHAR* OutputFileName) {

	HANDLE hOutputFile;
	DWORD dwBytesWritten;
	BOOL bErrorFlag;

	BYTE* FileData = ReadDataFromFile(FileName);

	HANDLE hfile = CreateFileA(FileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	EncryptDecryptCodeSection(FileData,1);
	hOutputFile = CreateFileA(OutputFileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hOutputFile == INVALID_HANDLE_VALUE) {
		printf("Faile TO open file for write Error Code %x\n", GetLastError());
		return -1;
	}

	DWORD FileSize = GetFileSize(hfile, NULL);
	bErrorFlag = WriteFile(hOutputFile, FileData, FileSize, &dwBytesWritten, NULL);

	if (FALSE == bErrorFlag) {
		printf("Failed To Write To File Error Code %x\n", GetLastError());
		return -1;
	}

	CloseHandle(hfile);
	CloseHandle(hOutputFile);

	return 0;
}


DWORD LoadEncryptedDll(CHAR* DllPath) {

	DWORD Result = 0;
	CONTEXT Context;
	Context.ContextFlags = CONTEXT_ALL;

	GetThreadContext(GetCurrentThread(), &Context);

	DWORD64 FunAddr = (DWORD64)GetProcAddress(LoadLibraryA("ntdll"), "ZwMapViewOfSection");

	Context.Dr7 |= 1 << (0 * 2);
	Context.Dr0 = FunAddr;
	Context.Dr7 |= 0x00 << ((0 * 4) + 16);
	Context.Dr7 |= sizeof(DWORD) << ((0 * 4) + 18);

	AddVectoredExceptionHandler(CALL_FIRST, ExceptionHandler);

	SetThreadContext(GetCurrentThread(), &Context);

	HMODULE Module = LoadLibraryA(DllPath);
	if (Module) {
		printf("Load Encrypted Library success Base Address is %p\n", Module);
		Result = 0;
	}
	else {
		printf("Load Encrypted Library failed  %p  %x\n", Module, GetLastError());
		Result = -1;
	}

	return Result;
}