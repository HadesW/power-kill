#pragma once
//global define
//#define UMDF_USING_NTSTATUS
#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <ntstatus.h>




//#ifndef NT_SUCCESS
//#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
//#endif

#define SystemHandleInformation 16

namespace utils
{
	namespace ntdll
	{
		typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
		{
			USHORT UniqueProcessId;
			USHORT CreatorBackTraceIndex;
			UCHAR ObjectTypeIndex;
			UCHAR HandleAttributes;
			USHORT HandleValue;
			PVOID Object;
			ULONG GrantedAccess;
		} SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

		typedef struct _SYSTEM_HANDLE_INFORMATION
		{
			ULONG NumberOfHandles;
			SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
		} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

		//__kernel_entry NTSTATUS NtQuerySystemInformation(IN SYSTEM_INFORMATION_CLASS SystemInformationClass,OUT PVOID   SystemInformation,IN ULONG SystemInformationLength,OUT PULONG  ReturnLength);
		typedef NTSTATUS(NTAPI* typfnNtQuerySystemInformation)(IN ULONG SystemInformationClass, OUT PVOID   SystemInformation, IN ULONG SystemInformationLength, OUT PULONG  ReturnLength);

	}

	BOOL EnableDebugPrivilege();
	DWORD GetPidByName(const wchar_t* name);
	DWORD64 FindProcessObject(DWORD pid);
	DWORD FindAccessibleProcess(DWORD64 object);
}