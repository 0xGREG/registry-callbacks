#pragma once
#include "ntos.h"
#include <ntddk.h>
#include <windef.h>

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

NTSTATUS DriverEntry(PDRIVER_OBJECT _0, PUNICODE_STRING _1);
NTSTATUS RegistryCallback(PVOID callbackContext, PVOID arg1, PVOID arg2);
PVOID GetModuleBase(LPCWSTR moduleName);
PVOID FindJmp(PVOID moduleBase);
NTSTATUS ReadVirtualMemory(PKERNEL_COPY_REQUEST req);
NTSTATUS WriteVirtualMemory(PKERNEL_COPY_REQUEST req);
NTSTATUS WriteProtectedVirtualMemory(PKERNEL_COPY_REQUEST req);
NTSTATUS GetProcessBaseAddress(PKERNEL_BASE_REQUEST req);
NTSTATUS IsRunning(PKERNEL_RUNNING_REQUEST req);