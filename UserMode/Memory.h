#pragma once
#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>

using namespace std;

typedef struct _KERNEL_COPY_REQUEST {
	ULONG ProcessId;
	PVOID Destination;
	PVOID Source;
	SIZE_T Size;
} KERNEL_COPY_REQUEST, *PKERNEL_COPY_REQUEST;

typedef struct _KERNEL_BASE_REQUEST {
	ULONG ProcessId;
	UINT64 ProcessBase;
} KERNEL_BASE_REQUEST, *PKERNEL_BASE_REQUEST;

typedef struct _KERNEL_RUNNING_REQUEST {
	UINT32 Running;
} KERNEL_RUNNING_REQUEST, *PKERNEL_RUNNING_REQUEST;

typedef struct _KERNEL_REQUEST {
	UINT32 Type;
	PVOID Instruction;
} KERNEL_REQUEST, *PKERNEL_REQUEST;

class Memory {
public:
	void WriteRegistry(uint32_t type, void* instruction) {
		HKEY hKey = NULL;

		RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Clipboard", 0, KEY_ALL_ACCESS, &hKey);

		if (hKey == NULL || hKey == INVALID_HANDLE_VALUE) {
			cout << "Registry error\n";
			return;
		}

		KERNEL_REQUEST request;

		request.Type = type;
		request.Instruction = instruction;

		void* pointer = &request;

		RegSetValueExA(hKey, "DisableAntiSpyware", 0, REG_QWORD, reinterpret_cast<BYTE*>(&pointer), sizeof(uint64_t));

		RegCloseKey(hKey);
	}

	template<typename T>
	T ReadMemory(uint64_t address) {
		T result{};

		KERNEL_COPY_REQUEST request;

		request.ProcessId = ProcessId;
		request.Source = reinterpret_cast<void*>(address);
		request.Destination = &result;
		request.Size = sizeof(T);

		WriteRegistry(0, &request);

		return result;
	}

	void WriteMemory(uint64_t address, void* value, size_t size) {
		KERNEL_COPY_REQUEST request;

		request.ProcessId = ProcessId;
		request.Source = value;
		request.Destination = reinterpret_cast<void*>(address);
		request.Size = size;

		WriteRegistry(1, &request);
	}

	template<typename T>
	void WriteMemory(uint64_t address, T value) {
		WriteMemory(address, &value, sizeof(T));
	}

	void WriteProtectedMemory(uint64_t address, void* value, size_t size) {
		KERNEL_COPY_REQUEST request;

		request.ProcessId = ProcessId;
		request.Source = value;
		request.Destination = reinterpret_cast<void*>(address);
		request.Size = size;

		WriteRegistry(2, &request);
	}

	uint64_t GetProcessBase() {
		KERNEL_BASE_REQUEST request;

		request.ProcessId = ProcessId;
		request.ProcessBase = 0;

		WriteRegistry(3, &request);

		return request.ProcessBase;
	}

	bool IsRunning() {
		KERNEL_RUNNING_REQUEST request;

		request.Running = 0;

		WriteRegistry(4, &request);

		return request.Running == 0x1337;
	}

	void AttachProcess(string processName) {
		const wstring wProcessName(processName.begin(), processName.end());

		PROCESSENTRY32 processInfo;
		processInfo.dwSize = sizeof(processInfo);

		HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
		if (processesSnapshot == INVALID_HANDLE_VALUE)
			return;

		Process32First(processesSnapshot, &processInfo);
		if (!wProcessName.compare(processInfo.szExeFile))
		{
			CloseHandle(processesSnapshot);
			ProcessId = processInfo.th32ProcessID;
			return;
		}

		while (Process32Next(processesSnapshot, &processInfo))
		{
			if (!wProcessName.compare(processInfo.szExeFile))
			{
				CloseHandle(processesSnapshot);
				ProcessId = processInfo.th32ProcessID;
				return;
			}
		}

		CloseHandle(processesSnapshot);
		return;
	}
private:
	ULONG ProcessId;
};