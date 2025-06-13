#include "ntinylib.hpp"


// Return base pointer to ntdll.dll when loaded from file into memroy
LPVOID MapNtdllFromDisk() {
    const wchar_t* path = L"C:\\Windows\\System32\\ntdll.dll";
    HANDLE hFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "CreateFileW failed: " << GetLastError() << "\n";
        return nullptr;
    }

    HANDLE hMap = CreateFileMappingW(hFile, NULL,
                                     PAGE_READONLY | SEC_IMAGE,
                                     0, 0, NULL);
    if (!hMap) {
        std::cerr << "CreateFileMappingW failed: " << GetLastError() << "\n";
        CloseHandle(hFile);
        return nullptr;
    }

    LPVOID base = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if (!base) {
        std::cerr << "MapViewOfFile failed: " << GetLastError() << "\n";
        CloseHandle(hMap);
        CloseHandle(hFile);
        return nullptr;
    }

    CloseHandle(hMap);
    CloseHandle(hFile);
    return base;
}


// Returns syscall number for a given function, or 0xFFFF if it is not found (or technically hooked but use the other functionto check)
WORD GetSyscallNumber(const std::string& funcName) {
    BYTE* base = (BYTE*) MapNtdllFromDisk();
    if (!base) return 0xFFFF;

    auto dos = (IMAGE_DOS_HEADER*)base;
    auto nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir.VirtualAddress) { UnmapViewOfFile(base); return 0xFFFF; }

    auto exp = (IMAGE_EXPORT_DIRECTORY*)(base + dir.VirtualAddress);
    auto names = (DWORD*)(base + exp->AddressOfNames);
    auto ords = (WORD*)(base + exp->AddressOfNameOrdinals);
    auto funcs = (DWORD*)(base + exp->AddressOfFunctions);

    WORD ssn = 0xFFFF;
    for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
        std::string name = (char*)(base + names[i]);
        if (_stricmp(name.c_str(), funcName.c_str()) != 0)
            continue;

        BYTE* fn = base + funcs[ords[i]];
        // Check if syscall stub is the pattern: 4C 8B D1 B8 ?? ?? 0F 05
        // <=> mov r10, rcx etc...
        if (fn[0] == 0x4C && fn[1] == 0x8B && fn[2] == 0xD1 && fn[3] == 0xB8) {
            ssn = *(WORD*)(fn + 4);
        }
    }

    UnmapViewOfFile(base);
    return ssn;
}


// check if functions is hooked or not by comparing in-memory version with the newly loaded from file version
// Return values :
// 0 : Not hooked
// 1 : hooked
// -1 : error (printed in standard error)

int IsFunctionHooked(const std::string& funcName) {
    LPVOID base = MapNtdllFromDisk();
    if (!base) {
        std::cerr << "Failed to map ntdll.dll from disk.\n";
        return false;
    }

    auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(reinterpret_cast<BYTE*>(base) + dos->e_lfanew);
    auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    // Ensure the export directory is valid
    if (!dir.VirtualAddress) {
        std::cerr << "No export directory found in ntdll.dll.\n";
        UnmapViewOfFile(base);
        return false;
    }

    // Retrieve the export directory
    auto exp = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(reinterpret_cast<BYTE*>(base) + dir.VirtualAddress);
    auto names = reinterpret_cast<DWORD*>(reinterpret_cast<BYTE*>(base) + exp->AddressOfNames);
    auto ords = reinterpret_cast<WORD*>(reinterpret_cast<BYTE*>(base) + exp->AddressOfNameOrdinals);
    auto funcs = reinterpret_cast<DWORD*>(reinterpret_cast<BYTE*>(base) + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
        std::string name = reinterpret_cast<char*>(reinterpret_cast<BYTE*>(base) + names[i]);
        if (_stricmp(name.c_str(), funcName.c_str()) != 0)
            continue;

        BYTE* fn = reinterpret_cast<BYTE*>(base) + funcs[ords[i]];

        // Read the first few bytes of the function in memory
        std::vector<BYTE> memBytes(16);
        SIZE_T bytesRead;
        if (!ReadProcessMemory(GetCurrentProcess(), fn, memBytes.data(), memBytes.size(), &bytesRead)) {
            std::cerr << "Failed to read memory at function address.\n";
            UnmapViewOfFile(base);
            return false;
        }

        // Retrieve the original bytes of the function from disk
        std::vector<BYTE> fileBytes(16);
        memcpy(fileBytes.data(), reinterpret_cast<BYTE*>(base) + funcs[ords[i]], fileBytes.size());

        // Compare the bytes with newly loaded bytes
        bool isHooked = memcmp(memBytes.data(), fileBytes.data(), memBytes.size()) != 0;

        UnmapViewOfFile(base);
        return isHooked;
    }

    std::cerr << "Function not found in export table: " << funcName << "\n";
    UnmapViewOfFile(base);
    return -1;
}
