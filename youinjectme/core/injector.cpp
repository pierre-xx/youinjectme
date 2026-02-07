#include "injector.h"

DWORD Injector::getProcessId(const std::string& name) {
	std::wstring wName(name.begin(), name.end());
	DWORD procId = 0;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hSnap != INVALID_HANDLE_VALUE) {
		PROCESSENTRY32 procEntry;
		procEntry.dwSize = sizeof(procEntry);

		if (Process32First(hSnap, &procEntry)) {
			do {
				if (!_wcsicmp(procEntry.szExeFile, wName.c_str())) {
					procId = procEntry.th32ProcessID;
					break;
				}
			} while (Process32NextW(hSnap, &procEntry));
		}
	}
	CloseHandle(hSnap);
	return procId;
}

void Injector::injectByRemoteThread() {
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, 0, this->pid);
	if (!hProc || hProc == INVALID_HANDLE_VALUE) {
		MessageBoxA(NULL, "OpenProcess error", "youinjectme", MB_OK | MB_ICONERROR);
		return;
	}

	void* loc = VirtualAllocEx(hProc, 0, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	const char* c = this->path.string().c_str();

	if (!WriteProcessMemory(hProc, loc, c, strlen(c) + 1, 0)) {
		MessageBoxA(NULL, "WriteProcessMemory error", "youinjectme", MB_OK | MB_ICONERROR);
		return;
	}

	HANDLE hThread = CreateRemoteThread(hProc, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, loc, 0, 0);
	if (!hThread) {
		MessageBoxA(NULL, "CreateRemoteThread error", "youinjectme", MB_OK | MB_ICONERROR);
		return;
	}

	if (hThread) {
		CloseHandle(hThread);
	}

	if (hProc) {
		CloseHandle(hProc);
	}
}

void Injector::selectDll() {
	HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
	if (FAILED(hr)) return;

	IFileOpenDialog* pFileOpen = nullptr;
	hr = CoCreateInstance(CLSID_FileOpenDialog, nullptr, CLSCTX_ALL, IID_IFileOpenDialog, reinterpret_cast<void**>(&pFileOpen));
	if (SUCCEEDED(hr)) {
		const COMDLG_FILTERSPEC filters[] =
		{
			{ L"DLL Files", L"*.dll" },
			{ L"All Files", L"*.*" }
		};

		pFileOpen->SetFileTypes(2, filters);
		pFileOpen->SetTitle(L"Select a DLL");
		hr = pFileOpen->Show(nullptr);

		if (SUCCEEDED(hr))
		{
			IShellItem* pItem;
			hr = pFileOpen->GetResult(&pItem);

			if (SUCCEEDED(hr))
			{
				PWSTR filePath = nullptr;
				hr = pItem->GetDisplayName(SIGDN_FILESYSPATH, &filePath);

				if (SUCCEEDED(hr))
				{
					this->path = filePath;
					CoTaskMemFree(filePath);
				}

				pItem->Release();
			}
		}
		pFileOpen->Release();
	}

	CoUninitialize();
}

void Injector::injectDll(const std::string& name) {
	if (this->path.empty()) {
		MessageBoxA(NULL, "No dll selected", "youinjectme", MB_OK | MB_ICONERROR);
		return;
	}

	this->pid = getProcessId(name);
	if (!this->pid) {
		MessageBoxA(NULL, "Process not found", "youinjectme", MB_OK | MB_ICONERROR);
		return;
	}

	if (this->manualMap) {
		InjectByManualMapping(this->pid, this->path.string());
	}
	else {
		this->injectByRemoteThread();
	}
}