#include <windows.h>
#include <iostream>
#include <stdio.h>
#include <string>
#include <vector>
#include <psapi.h>
#include <memoryapi.h>

struct ExportedFunc {
    std::string name;
    DWORD      rva;
    WORD       ordinal;
};

struct SyscallEntry {
    std::string name;
    WORD        number;
    BYTE* addr;  // address of stub in base
};


LPVOID MapNtdllFromDisk();
DWORD GetSyscallNumber(const std::string& funcName);
int IsFunctionHooked(const std::string& funcName);
