#pragma once

// Suppress macro redefinition warnings and VCRuntime issues
#pragma warning(push)
#pragma warning(disable: 4005 4083)

#include <stdint.h>
#include <ntdef.h>
#include <ntifs.h>
#include <ntddk.h>
#include <ntimage.h>
#include <windef.h>
#include <intrin.h>
#include <ntstrsafe.h>
#include <wdmsec.h>
#include <new.h>

#pragma warning(pop)

#define LOG(FORMAT, ...)							DbgPrint(FORMAT, __VA_ARGS__);
#define DeviceName									L"\\Device\\KMInjector"
#define DosDeviceName								L"\\??\\KMInjector"
#define s_SDDL_DEVOBJ_SYS_ALL_ADM_RWX_WORLD_R		L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;WD)"

//ioctl
#define IOCTL_INJECTOR_RUN CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

typedef struct _INJECTION_INFO
{
	ULONG TargetPid;
	void* DllBuffer;
}INJECTION_INFO, * PINJECTION_INFO;

// Direct function declarations for undocumented functions
extern "C" NTSTATUS NTAPI MmCopyVirtualMemory(
    PEPROCESS SourceProcess,
    PVOID SourceAddress,
    PEPROCESS TargetProcess,
    PVOID TargetAddress,
    SIZE_T BufferSize,
    KPROCESSOR_MODE PreviousMode,
    PSIZE_T ReturnSize
);

extern "C" NTKERNELAPI NTSTATUS RtlCreateUserThread(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _In_ BOOLEAN CreateSuspended,
    _In_ ULONG StackZeroBits,
    _Inout_opt_ PULONG_PTR StackReserved,
    _Inout_opt_ PULONG_PTR StackCommit,
    _In_ PVOID StartAddress,
    _In_opt_ PVOID StartParameter,
    _Out_opt_ PHANDLE ThreadHandle,
    _Out_opt_ PCLIENT_ID ClientId
);