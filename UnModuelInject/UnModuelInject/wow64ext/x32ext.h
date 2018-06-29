#pragma once

#ifndef _WIN64
#include <Windows.h>

BOOL Wow64Injectx64(HANDLE hProcess, LPCTSTR lpDllFilePath);

#endif
