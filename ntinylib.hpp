#include <windows.h>
#include <iostream>
#include <stdio.h>
#include <string>
#include <vector>
#include <psapi.h>
#include <memoryapi.h>



LPVOID MapNtdllFromDisk();
DWORD GetSyscallNumber(const std::string& funcName);
int IsFunctionHooked(const std::string& funcName);
