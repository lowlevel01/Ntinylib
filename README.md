# Ntinylib
Tiny x64 Windows C++ library that has functions to get SSN number of a specific API function, Check if a specific API is hooked ( and More in the future)

# Library Functions
###### More function will be added in the future

```
LPVOID MapNtdllFromDisk();  // Returns base pointer to loaded-from-disk ntdll.dll
WORD GetSyscallNumber(const std::string& funcName);  // returns SSN Numver of funcName or 0xFFFF in case something went wrong
int IsFunctionHooked(const std::string& funcName);  // returns 1 if funcName is hooked, 0 is not and -1 in case of error
```

# Usage

Copy the files to your project and add ```#include "ntinylib.hpp"``` inside the file that contains the includes depending on your projects.

