#include "manual_map.h"

const size_t REMOTE_PE_HEADER_ALLOC_SIZE = 4096;
const size_t REMOTE_RELOC_STUB_ALLOC_SIZE = 4096;

DWORD_PTR PointerToRva(const void* const baseAddress, const void* const offset) {
	return reinterpret_cast<DWORD_PTR>(baseAddress) - reinterpret_cast<DWORD_PTR>(offset);
}

std::vector<char> GetDllFileBytes(const std::string& fullModulePath) {

	std::ifstream fileStream(fullModulePath.c_str(), std::ios::in | std::ios::binary | std::ios::ate);

	const auto fileSize{ fileStream.tellg() };
	fileStream.seekg(0, std::ios::beg);

	std::vector<char> fileBytes(fileSize);
	fileStream.read(fileBytes.data(), fileSize);

	return fileBytes;
}

void* WriteDllFileBytesToProcess(const HANDLE processHandle,
	const std::vector<char>& fileBytes) {

	const auto dosHeader{ reinterpret_cast<const IMAGE_DOS_HEADER*>(fileBytes.data()) };
	const auto ntHeader{ reinterpret_cast<const IMAGE_NT_HEADERS*>(fileBytes.data() + dosHeader->e_lfanew) };

	const auto remoteBaseAddress{ VirtualAllocEx(processHandle, nullptr, ntHeader->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE) };
	if (remoteBaseAddress == nullptr) {
		MessageBoxA(NULL, "VirtualAllocEx error", "youinjectme", MB_OK | MB_ICONERROR);
	}

	const auto* currentSection{ IMAGE_FIRST_SECTION(ntHeader) };
	for (size_t i{}; i < ntHeader->FileHeader.NumberOfSections; i++) {

		SIZE_T bytesWritten{};
		auto result{ WriteProcessMemory(processHandle, static_cast<char*>(remoteBaseAddress) + currentSection->VirtualAddress, fileBytes.data() + currentSection->PointerToRawData, currentSection->SizeOfRawData, &bytesWritten) };
		if (result == 0 || bytesWritten == 0) {
			MessageBoxA(NULL, "WriteProcessMemory error", "youinjectme", MB_OK | MB_ICONERROR);
		}

		currentSection++;
	}

	SIZE_T bytesWritten{};
	const auto result{ WriteProcessMemory(processHandle, remoteBaseAddress, fileBytes.data(), REMOTE_PE_HEADER_ALLOC_SIZE, &bytesWritten) };
	if (result == 0 || bytesWritten == 0) {
		MessageBoxA(NULL, "WriteProcessMemory error", "youinjectme", MB_OK | MB_ICONERROR);
	}

	return remoteBaseAddress;
}

void* GetRemoteModuleFunctionAddress(const std::string moduleName,
	const std::string functionName, const DWORD processId) {

	void* localModuleBaseAddress{ GetModuleHandleA(moduleName.c_str()) };
	if (localModuleBaseAddress == nullptr) {
		localModuleBaseAddress = LoadLibraryA(moduleName.c_str());
		if (localModuleBaseAddress == nullptr) {
			MessageBoxA(NULL, "LoadLibraryA error", "youinjectme", MB_OK | MB_ICONERROR);
		}
	}

	const void* const localFunctionAddress{ GetProcAddress(static_cast<HMODULE>(localModuleBaseAddress), functionName.c_str()) };

	if (localFunctionAddress == nullptr) {
		MessageBoxA(NULL, "GetProcAddress error", "youinjectme", MB_OK | MB_ICONERROR);
	}

	const auto functionOffset{ PointerToRva(localFunctionAddress, localModuleBaseAddress) };

	const auto snapshotHandle{ CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, processId) };
	if (snapshotHandle == INVALID_HANDLE_VALUE) {
		MessageBoxA(NULL, "CreateToolhelp32Snapshot error", "youinjectme", MB_OK | MB_ICONERROR);
	}

	MODULEENTRY32 module{
		.dwSize = sizeof(MODULEENTRY32)
	};

	if (!Module32First(snapshotHandle, &module)) {
		MessageBoxA(NULL, "Module32First error", "youinjectme", MB_OK | MB_ICONERROR);
	}

	do {
		std::string currentModuleName;

		#ifdef UNICODE
				std::wstring wName(module.szModule);
				currentModuleName.assign(wName.begin(), wName.end());
		#else
				currentModuleName = module.szModule;
		#endif

		std::transform(currentModuleName.begin(), currentModuleName.end(), currentModuleName.begin(),
			[](unsigned char letter) { return std::tolower(letter); });
		if (currentModuleName == moduleName) {
			return reinterpret_cast<void*>(module.modBaseAddr + functionOffset);
		}

	} while (Module32Next(snapshotHandle, &module));

	return nullptr;
}


void RelocationStub(RelocationStubParameters* parameters) {

	const auto dosHeader{ reinterpret_cast<IMAGE_DOS_HEADER*>(parameters->remoteDllBaseAddress) };
	const auto ntHeader{ reinterpret_cast<IMAGE_NT_HEADERS*>(reinterpret_cast<DWORD_PTR>(parameters->remoteDllBaseAddress) + dosHeader->e_lfanew) };

	const auto relocationOffset{ reinterpret_cast<DWORD_PTR>(parameters->remoteDllBaseAddress) - ntHeader->OptionalHeader.ImageBase };

	typedef struct {
		WORD offset : 12;
		WORD type : 4;
	} RELOCATION_INFO;

	const auto* baseRelocationDirectoryEntry{
		reinterpret_cast<IMAGE_BASE_RELOCATION*>(
			reinterpret_cast<DWORD_PTR>(parameters->remoteDllBaseAddress) +
			ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
				.VirtualAddress) };

	while (baseRelocationDirectoryEntry->VirtualAddress != 0) {

		const auto relocationCount{
			(baseRelocationDirectoryEntry->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) /
			sizeof(RELOCATION_INFO) };

		const auto* baseRelocationInfo{ reinterpret_cast<RELOCATION_INFO*>(
			reinterpret_cast<DWORD_PTR>(
				baseRelocationDirectoryEntry) + 1) };

		for (size_t i{}; i < relocationCount; i++, baseRelocationInfo++) {
			if (baseRelocationInfo->type == IMAGE_REL_BASED_DIR64) {
				const auto relocFixAddress{ reinterpret_cast<DWORD*>(
					reinterpret_cast<DWORD_PTR>(parameters->remoteDllBaseAddress) +
					baseRelocationDirectoryEntry->VirtualAddress +
					baseRelocationInfo->offset) };
				*relocFixAddress += static_cast<DWORD>(relocationOffset);
			}
		}

		baseRelocationDirectoryEntry = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
			reinterpret_cast<DWORD_PTR>(baseRelocationDirectoryEntry) +
			baseRelocationDirectoryEntry->SizeOfBlock);
	}

	const auto* baseImportsDirectory{
		reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
			reinterpret_cast<DWORD_PTR>(parameters->remoteDllBaseAddress) +
			ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
				.VirtualAddress) };

	for (size_t index{}; baseImportsDirectory[index].Characteristics != 0; index++) {
		const auto* const moduleName{ RvaToPointer(char*,
			parameters->remoteDllBaseAddress,
			baseImportsDirectory[index].Name) };
		const auto loadedModuleHandle{
			parameters->remoteLoadLibraryAAddress(moduleName) };

		auto* addressTableEntry{ RvaToPointer(IMAGE_THUNK_DATA*,
			parameters->remoteDllBaseAddress,
			baseImportsDirectory[index].FirstThunk) };
		const auto* nameTableEntry{ RvaToPointer(IMAGE_THUNK_DATA*,
			parameters->remoteDllBaseAddress,
			baseImportsDirectory[index].OriginalFirstThunk) };

		if (nameTableEntry == nullptr) {
			nameTableEntry = addressTableEntry;
		}

		for (; nameTableEntry->u1.Function != 0;
			nameTableEntry++, addressTableEntry++) {

			const auto* const importedFunction{ RvaToPointer(IMAGE_IMPORT_BY_NAME*,
				parameters->remoteDllBaseAddress, nameTableEntry->u1.AddressOfData)
			};

			if (nameTableEntry->u1.Ordinal & IMAGE_ORDINAL_FLAG) {

				addressTableEntry->u1.Function = reinterpret_cast<ULONGLONG>(
					parameters->remoteGetProcAddressAddress(loadedModuleHandle,
						MAKEINTRESOURCEA(nameTableEntry->u1.Ordinal)));
			}
			else {
				addressTableEntry->u1.Function = reinterpret_cast<ULONGLONG>(
					parameters->remoteGetProcAddressAddress(loadedModuleHandle,
						importedFunction->Name));
			}
		}
	}

	if (ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size > 0) {
		const auto* baseTlsEntries{
			reinterpret_cast<IMAGE_TLS_DIRECTORY*>(
				reinterpret_cast<DWORD_PTR>(parameters->remoteDllBaseAddress) +
				ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS]
					.VirtualAddress) };

		const auto* tlsCallback{ reinterpret_cast<PIMAGE_TLS_CALLBACK*>(
			baseTlsEntries->AddressOfCallBacks) };
		while (tlsCallback != nullptr) {
			(*tlsCallback)(parameters->remoteDllBaseAddress, DLL_PROCESS_ATTACH,
				nullptr);
			tlsCallback++;
		}
	}

	using DllMainPtr = BOOL(__stdcall*)(HINSTANCE hinstDLL,
		DWORD fdwReason, LPVOID lpvReserved);

	const auto DllMain{ reinterpret_cast<DllMainPtr>(
		reinterpret_cast<DWORD_PTR>(parameters->remoteDllBaseAddress) +
		ntHeader->OptionalHeader.AddressOfEntryPoint) };

	DllMain(reinterpret_cast<HINSTANCE>(parameters->remoteDllBaseAddress),
		DLL_PROCESS_ATTACH, nullptr);
}

std::pair<void*, void*> WriteRelocationStubToTargetProcess(
	const HANDLE processHandle, const RelocationStubParameters& parameters) {

	auto* const remoteParametersAddress{ VirtualAllocEx(processHandle, nullptr,
		REMOTE_RELOC_STUB_ALLOC_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE) };
	if (remoteParametersAddress == nullptr) {
		MessageBoxA(NULL, "VirtualAllocEx error", "youinjectme", MB_OK | MB_ICONERROR);

	}

	SIZE_T bytesWritten{};
	auto result{ WriteProcessMemory(processHandle, remoteParametersAddress,
		&parameters, sizeof(RelocationStubParameters),
		&bytesWritten) };
	if (result == 0 || bytesWritten == 0) {
		MessageBoxA(NULL, "WriteProcessMemory error", "youinjectme", MB_OK | MB_ICONERROR);
	}

	auto* const remoteRelocationStubAddress{ VirtualAllocEx(processHandle, nullptr,
		REMOTE_RELOC_STUB_ALLOC_SIZE,
		MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE) };
	if (remoteRelocationStubAddress == nullptr) {
		MessageBoxA(NULL, "VirtualAllocEx error", "youinjectme", MB_OK | MB_ICONERROR);
	}

	result = WriteProcessMemory(processHandle, remoteRelocationStubAddress,
		RelocationStub, REMOTE_RELOC_STUB_ALLOC_SIZE, &bytesWritten);
	if (result == 0 || bytesWritten == 0) {
		MessageBoxA(NULL, "WriteProcessMemory error", "youinjectme", MB_OK | MB_ICONERROR);
	}

	return std::make_pair(remoteRelocationStubAddress, remoteParametersAddress);
}

HANDLE GetTargetProcessHandle(const DWORD processId) {

	const auto processHandle{ OpenProcess(
		PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
		PROCESS_VM_WRITE, false, processId) };
	if (processHandle == nullptr) {
		MessageBoxA(NULL, "OpenProcess error", "youinjectme", MB_OK | MB_ICONERROR);
	}

	return processHandle;
}


void InjectByManualMapping(const DWORD processId,
	const std::string& fullModulePath) {

	const auto processHandle{ GetTargetProcessHandle(processId) };
	const auto fileBytes{ GetDllFileBytes(fullModulePath) };

	auto* const remoteDllBaseAddress{ WriteDllFileBytesToProcess(
		processHandle, fileBytes) };
	auto* const remoteLoadLibraryAddress{ GetRemoteModuleFunctionAddress(
		"kernel32.dll", "LoadLibraryA", processId) };
	auto* const remoteGetProcAddressAddress{ GetRemoteModuleFunctionAddress(
		"kernel32.dll", "GetProcAddress", processId) };

	const RelocationStubParameters parameters{
		.remoteDllBaseAddress = remoteDllBaseAddress,
		.remoteLoadLibraryAAddress = reinterpret_cast<LoadLibraryAPtr>(
			remoteLoadLibraryAddress),
		.remoteGetProcAddressAddress = reinterpret_cast<GetProcAddressPtr>(
			remoteGetProcAddressAddress)
	};

	const auto relocationInfo{
		WriteRelocationStubToTargetProcess(processHandle, parameters) };

	const auto remoteThread{ CreateRemoteThreadEx(processHandle, nullptr, 0,
		reinterpret_cast<LPTHREAD_START_ROUTINE>(relocationInfo.first),
		relocationInfo.second, 0, nullptr, 0) };
	if (remoteThread == nullptr) {
		MessageBoxA(NULL, "CreateRemoteThreadEx error", "youinjectme", MB_OK | MB_ICONERROR);
	}
}