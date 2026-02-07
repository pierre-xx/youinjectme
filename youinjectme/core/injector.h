#pragma once
#include <iostream>
#include <windows.h>
#include <TlHelp32.h>
#include <shobjidl.h>
#include <filesystem>

class Injector {
private:
	DWORD pid = 0;

	std::filesystem::path path;

	DWORD getProcessId(const std::string& name);
public:
	void selectDll();
	void injectDll(const std::string& name);
};