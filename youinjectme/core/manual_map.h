#pragma once
#include <iostream>
#include <windows.h>
#include <TlHelp32.h>
#include <vector>
#include <algorithm>
#include <fstream>

/*
	derived from the codereversing map implementation: https://www.codereversing.com/archives/652

	licensed under the GNU AFFERO GENERAL PUBLIC LICENSE (AGPL)

	thank you for the manual mapping implementation!!
	
	modifications: unicode implementation
*/

#define RvaToPointer(type, baseAddress, offset) \
    reinterpret_cast<type>( \
        reinterpret_cast<DWORD_PTR>(baseAddress) + offset)

using LoadLibraryAPtr = HMODULE(__stdcall*)(LPCSTR lpLibFileName);
using GetProcAddressPtr = FARPROC(__stdcall*)(HMODULE hModule, LPCSTR  lpProcName);

typedef struct {
	void* const remoteDllBaseAddress;
	LoadLibraryAPtr remoteLoadLibraryAAddress;
	GetProcAddressPtr remoteGetProcAddressAddress;
} RelocationStubParameters;

std::vector<char> GetDllFileBytes(const std::string& fullModulePath);
void* WriteDllFileBytesToProcess(const HANDLE processHandle, const std::vector<char>& fileBytes);
void* GetRemoteModuleFunctionAddress(const std::string moduleName, const std::string functionName, const DWORD processId);
void RelocationStub(RelocationStubParameters* parameters);
std::pair<void*, void*> WriteRelocationStubToTargetProcess(const HANDLE processHandle, const RelocationStubParameters& parameters);
HANDLE GetTargetProcessHandle(const DWORD processId);
void InjectByManualMapping(const DWORD processId, const std::string& fullModulePath);
