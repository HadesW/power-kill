#pragma once

#include <Windows.h>
#include <winnt.h>
#include <winternl.h>

namespace ScStdio {
	BOOL MalCode(DWORD pid);
	BOOL WriteShellcodeToDisk();
}