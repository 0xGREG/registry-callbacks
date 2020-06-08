#include "Driver.h"

LARGE_INTEGER CmCookie = { 0x115 };
UNICODE_STRING MonitoredKey;

NTSTATUS DriverEntry(PDRIVER_OBJECT _0, PUNICODE_STRING _1) {
	PVOID classpnp = GetModuleBase(L"classpnp.sys");

	if (classpnp == NULL)
		return STATUS_INVALID_HANDLE;

	PVOID jmp = FindJmp(classpnp);

	if (jmp == NULL)
		return STATUS_NOT_FOUND;

	RtlInitUnicodeString(&MonitoredKey, L"DisableAntiSpyware");

	return CmRegisterCallback((PEX_CALLBACK_FUNCTION)jmp, (PVOID)&RegistryCallback, &CmCookie);
}

NTSTATUS RegistryCallback(PVOID callbackContext, PVOID arg1, PVOID arg2) {
	UNREFERENCED_PARAMETER(callbackContext);

	if ((REG_NOTIFY_CLASS)arg1 != RegNtPostSetValueKey)
		return STATUS_SUCCESS;

	PREG_POST_OPERATION_INFORMATION postInfo = (PREG_POST_OPERATION_INFORMATION)arg2;

	PREG_SET_VALUE_KEY_INFORMATION preInfo = (PREG_SET_VALUE_KEY_INFORMATION)postInfo->PreInformation;

	if (preInfo->DataSize != 0x8)
		return STATUS_SUCCESS;

	if (!RtlEqualUnicodeString((PCUNICODE_STRING)preInfo->ValueName, (PCUNICODE_STRING)&MonitoredKey, TRUE))
		return STATUS_SUCCESS;

	PKERNEL_REQUEST Data = *(PKERNEL_REQUEST*)preInfo->Data;

	if (Data->Type == 0)
		ReadVirtualMemory(Data->Instruction);
	else if (Data->Type == 1)
		WriteVirtualMemory(Data->Instruction);
	else if (Data->Type == 2)
		WriteProtectedVirtualMemory(Data->Instruction);
	else if (Data->Type == 3)
		GetProcessBaseAddress(Data->Instruction);
	else if (Data->Type == 4)
		IsRunning(Data->Instruction);

	return STATUS_SUCCESS;
}

PVOID GetModuleBase(LPCWSTR moduleName) {
	PLIST_ENTRY _PsLoadedModuleList = (PLIST_ENTRY)PsLoadedModuleList;

	if (!_PsLoadedModuleList)
		return (PVOID)NULL;

	UNICODE_STRING name;
	RtlInitUnicodeString(&name, moduleName);

	for (PLIST_ENTRY link = _PsLoadedModuleList; link != _PsLoadedModuleList->Blink; link = link->Flink)
	{
		PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(link, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

		if (RtlEqualUnicodeString((PCUNICODE_STRING)&entry->BaseDllName, (PCUNICODE_STRING)&name, TRUE)) {
			return (PVOID)entry->DllBase;
		}
	}

	return (PVOID)NULL;
}

PVOID FindJmp(PVOID moduleBase) {
	CONST PIMAGE_NT_HEADERS ntHeader = RtlImageNtHeader(moduleBase);

	CONST PIMAGE_SECTION_HEADER firstSection = IMAGE_FIRST_SECTION(ntHeader);

	for (PIMAGE_SECTION_HEADER section = firstSection; section < firstSection + ntHeader->FileHeader.NumberOfSections; section++)
	{
		if (!section)
			continue;

		if (!(section->Characteristics & 0x20000000) || !(section->Characteristics & 0x08000000))
			continue;

		CONST UINT64 sectionStart = (UINT64)moduleBase + section->VirtualAddress;
		CONST UINT64 sectionSize = section->SizeOfRawData;

		for (UINT64 current = sectionStart; current < (sectionStart + sectionSize); current++)
		{
			if (*(USHORT*)current == 0xe1ff) // jmp ecx: FF E1
				return (PVOID)current;
		}
	}

	return (PVOID)NULL;
}

NTSTATUS ReadVirtualMemory(PKERNEL_COPY_REQUEST req) {
	PEPROCESS process;

	NTSTATUS status = PsLookupProcessByProcessId(req->ProcessId, &process);

	if (!NT_SUCCESS(status))
		return status;

	SIZE_T bytes;

	status = MmCopyVirtualMemory(process, req->Source, PsGetCurrentProcess(), req->Destination, req->Size, UserMode, &bytes);

	ObDereferenceObject(process);

	return status;
}

NTSTATUS WriteVirtualMemory(PKERNEL_COPY_REQUEST req) {
	PEPROCESS process;

	NTSTATUS status = PsLookupProcessByProcessId(req->ProcessId, &process);

	if (!NT_SUCCESS(status))
		return status;

	SIZE_T bytes;

	status = MmCopyVirtualMemory(PsGetCurrentProcess(), req->Source, process, req->Destination, req->Size, UserMode, &bytes);

	ObDereferenceObject(process);

	return status;
}

NTSTATUS WriteProtectedVirtualMemory(PKERNEL_COPY_REQUEST req) {
	PEPROCESS pProcess;

	NTSTATUS status = PsLookupProcessByProcessId(req->ProcessId, &pProcess);

	if (!NT_SUCCESS(status))
		return status;

	NTSTATUS Status = STATUS_INVALID_ADDRESS;
	KAPC_STATE APC;

	PVOID Address = (PVOID)req->Destination;
	PVOID ProtectedAddress = (PVOID)req->Destination;
	SIZE_T Size = req->Size;
	SIZE_T ProtectedSize = req->Size;

	PVOID* Buffer = (PVOID*)ExAllocatePool(NonPagedPool, Size);
	if (Buffer == NULL) {
		return STATUS_MEMORY_NOT_ALLOCATED;
	}

	RtlSecureZeroMemory(Buffer, Size);

	__try {
		memcpy(Buffer, req->Source, Size);

		KeStackAttachProcess(pProcess, &APC);

		ULONG OldProtection;
		Status = ZwProtectVirtualMemory(ZwCurrentProcess(), &ProtectedAddress, &ProtectedSize, PAGE_EXECUTE_READWRITE, &OldProtection);
		if (!NT_SUCCESS(Status)) {
			KeUnstackDetachProcess(&APC);

			ExFreePool(Buffer);

			return Status;
		}

		ProtectedAddress = Address;
		ProtectedSize = Size;

		MEMORY_BASIC_INFORMATION info;
		Status = ZwQueryVirtualMemory(ZwCurrentProcess(), Address, MemoryBasicInformation, &info, sizeof(MEMORY_BASIC_INFORMATION), NULL);
		if (!NT_SUCCESS(Status)) {
			KeUnstackDetachProcess(&APC);

			ExFreePool(Buffer);

			return Status;
		}

		if (!(info.State & MEM_COMMIT)) {
			ZwProtectVirtualMemory(ZwCurrentProcess(), &ProtectedAddress, &ProtectedSize, OldProtection, &OldProtection);

			KeUnstackDetachProcess(&APC);

			ExFreePool(Buffer);

			Status = STATUS_ACCESS_DENIED;

			return Status;
		}

		memcpy(Address, Buffer, Size);

		ZwProtectVirtualMemory(ZwCurrentProcess(), &ProtectedAddress, &ProtectedSize, OldProtection, &OldProtection);

		KeUnstackDetachProcess(&APC);

		Status = STATUS_SUCCESS;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		KeUnstackDetachProcess(&APC);
	}

	ExFreePool(Buffer);

	return Status;
}

NTSTATUS GetProcessBaseAddress(PKERNEL_BASE_REQUEST req) {
	PEPROCESS process;

	NTSTATUS status = PsLookupProcessByProcessId(req->ProcessId, &process);

	if (!NT_SUCCESS(status))
		return status;

	req->ProcessBase = (UINT64)PsGetProcessSectionBaseAddress(process);

	return STATUS_SUCCESS;
}

NTSTATUS IsRunning(PKERNEL_RUNNING_REQUEST req) {
	req->Running = 0x1337;

	return STATUS_SUCCESS;	
}