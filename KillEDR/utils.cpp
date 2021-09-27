#include "utils.hpp"


namespace utils
{
	BOOL EnableDebugPrivilege()
	{
		BOOL ret = FALSE;
		HANDLE token = nullptr;

		do
		{
			if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &token))
			{
				break;
			}

			TOKEN_PRIVILEGES privileges;
			privileges.PrivilegeCount = 1;
			if (!LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &privileges.Privileges[0].Luid))
			{
				break;
			}

			privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
			if (!AdjustTokenPrivileges(token, FALSE, &privileges, sizeof(privileges), NULL, NULL))
			{
				break;
			}

			ret = TRUE;
		} while (false);

		if (token)
		{
			CloseHandle(token);
		}

		return ret;
	}

	DWORD GetPidByName(const wchar_t* name)
	{
		DWORD pid = 0;
		HANDLE snapshot = INVALID_HANDLE_VALUE;

		do
		{
			PROCESSENTRY32W entry;
			entry.dwSize = sizeof(entry);
			snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
			if (snapshot == INVALID_HANDLE_VALUE)
			{
				break;
			}

			if (!Process32FirstW(snapshot, &entry))
			{
				break;
			}

			do
			{
				if (_wcsicmp(name, entry.szExeFile) == 0)
				{
					pid = entry.th32ProcessID;
					break;
				}
			} while (Process32NextW(snapshot, &entry));

		} while (false);

		if (snapshot)
		{
			CloseHandle(snapshot);
		}

		return pid;
	}

	DWORD64 FindProcessObject(DWORD pid)
	{
		DWORD64 object = 0;
		HANDLE handle = nullptr;
		PVOID buffer = nullptr;

		do 
		{
			// test open target process handle with limit access
			handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
			if (handle==nullptr)
			{
				break;
			}

			// Find Ntdll
			HMODULE module = GetModuleHandleA("ntdll.dll");
			if (module == nullptr)
			{
				break;
			}

			// Find Nt Function
			using FunctionT = ntdll::typfnNtQuerySystemInformation;
			FunctionT pfnNtQuerySystemInformation = (FunctionT)GetProcAddress(module, "NtQuerySystemInformation");
			if (pfnNtQuerySystemInformation == nullptr)
			{
				break;
			}

			DWORD size = 0x10000;
			NTSTATUS status = STATUS_SUCCESS;
			// alloc tmp buffer
			buffer = malloc(size);
			if (!buffer)
			{
				break;
			}

			do
			{
				// realloc large enough buffer
				buffer = realloc(buffer, size = 2 * size);
				if (!buffer)
				{
					break;
				}

				// get system handle info
				status = pfnNtQuerySystemInformation(SystemHandleInformation, buffer, size, nullptr);

			} while (status == STATUS_INFO_LENGTH_MISMATCH);

			if (!NT_SUCCESS(status) || buffer == nullptr)
			{
				break;
			}

			// system handle
			ntdll::PSYSTEM_HANDLE_INFORMATION sys_handle = (ntdll::PSYSTEM_HANDLE_INFORMATION)buffer;

			for (size_t i = 0; i < sys_handle->NumberOfHandles; i++)
			{
				// handle info
				ntdll::SYSTEM_HANDLE_TABLE_ENTRY_INFO info = sys_handle->Handles[i];

				//  in current process opened target process handle
				if (info.UniqueProcessId==GetCurrentProcessId()&&(HANDLE)info.HandleValue==handle)
				{
					object = (DWORD64)info.Object;
					break;
				}
			}

		} while (false);

		if (handle)
		{
			CloseHandle(handle);
		}

		if (buffer)
		{
			free(buffer);
		}

		return object;
	}

	DWORD FindAccessibleProcess(DWORD64 object)
	{
		DWORD ret = 0;
		PVOID buffer = nullptr;
		HANDLE handle = nullptr;

		do
		{
			// Find Ntdll
			HMODULE module = GetModuleHandleA("ntdll.dll");
			if (module == nullptr)
			{
				break;
			}

			// Find Nt Function
			using FunctionT = ntdll::typfnNtQuerySystemInformation;
			FunctionT pfnNtQuerySystemInformation = (FunctionT)GetProcAddress(module, "NtQuerySystemInformation");
			if (pfnNtQuerySystemInformation == nullptr)
			{
				break;
			}

			DWORD size = 0x10000;
			NTSTATUS status = STATUS_SUCCESS;
			// alloc tmp buffer
			buffer = malloc(size);
			if (!buffer)
			{
				break;
			}

			do
			{
				// realloc large enough buffer
				buffer = realloc(buffer, size = 2 * size);
				if (!buffer)
				{
					break;
				}

				// get system handle info
				status = pfnNtQuerySystemInformation(SystemHandleInformation, buffer, size, nullptr);

			} while (status == STATUS_INFO_LENGTH_MISMATCH);

			if (!NT_SUCCESS(status) || buffer == nullptr)
			{
				break;
			}

			// system handle
			ntdll::PSYSTEM_HANDLE_INFORMATION sys_handle = (ntdll::PSYSTEM_HANDLE_INFORMATION)buffer;

			for (size_t i = 0; i < sys_handle->NumberOfHandles; i++)
			{
				// handle info
				ntdll::SYSTEM_HANDLE_TABLE_ENTRY_INFO info = sys_handle->Handles[i];

				// TypeName=Process,TypeIndex=7
				if (info.ObjectTypeIndex != 7)
				{
					continue;
				}

				// exclude system process
				if (info.UniqueProcessId == 0 || info.UniqueProcessId == 4)
				{
					continue;
				}

				// target process
				if ((DWORD64)info.Object != object)
				{
					continue;
				}

				// access enough
				ACCESS_MASK access = info.GrantedAccess;
				ACCESS_MASK power = PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE;
				if ((access & power) != power)
				{
					continue;
				}

				// test can be opened with read and write access
				handle = OpenProcess(power, FALSE, info.UniqueProcessId);
				if (handle != nullptr)
				{
					// is 64bit process
					BOOL wow64 = TRUE;
					if (IsWow64Process(handle, &wow64)&&wow64==FALSE)
					{
						ret = info.UniqueProcessId;
						break;
					}
				}
			}

		} while (false);

		// free
		if (buffer)
		{
			free(buffer);
		}

		if (handle)
		{
			CloseHandle(handle);
		}

		return ret;
	}

}