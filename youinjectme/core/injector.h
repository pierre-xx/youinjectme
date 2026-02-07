#pragma once
#include <iostream>
#include <windows.h>
#include <TlHelp32.h>
#include <shobjidl.h>
#include <filesystem>
#include <fstream>
#include "manual_map.h"

class Injector {
private:
	DWORD pid = 0;
	std::filesystem::path path;
	bool manualMap = false;

	DWORD getProcessId(const std::string& name);
	void injectByRemoteThread();
public:
	void selectDll();
	void injectDll(const std::string& name);

	void setManualMap(bool v) { this->manualMap = v; }
	bool isManualMap() { return this->manualMap; }
};