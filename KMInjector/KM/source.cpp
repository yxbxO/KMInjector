#pragma once
#include "stdafx.h"
#include "inject.h"

PDEVICE_OBJECT DeviceObject;
UNICODE_STRING deviceName, symLinkName;
EX_RUNDOWN_REF PendingOperations;

void DriverUnload(
	_In_ PDRIVER_OBJECT DriverObject
)
{
	ExWaitForRundownProtectionRelease(&PendingOperations);
	IoDeleteDevice(DriverObject->DeviceObject);
	IoDeleteSymbolicLink(&symLinkName);
	LOG("[*] injector unloaded\n");
}

NTSTATUS MJCreateCloseDispatch(PDEVICE_OBJECT DeviceObj, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObj);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS DeviceControlHandler(PDEVICE_OBJECT DeviceObj, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObj);
	
	NTSTATUS Status;
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
	ULONG controlCode = stack->Parameters.DeviceIoControl.IoControlCode;
	
	Status = STATUS_SUCCESS;
	switch (controlCode)
	{
		case IOCTL_INJECTOR_RUN:
		{
			LOG("[*] IOCTL_INJECTOR_RUN received\n");
			PINJECTION_INFO InjectionInfo = (PINJECTION_INFO)Irp->AssociatedIrp.SystemBuffer;
			if (InjectionInfo == nullptr) {
				LOG("[*] Invalid Injection Info\n");
				break;
			}
			if (InjectionInfo->TargetPid == 0 || InjectionInfo->DllBuffer == nullptr) {
				LOG("[*] Invalid Parameters: PID=0x%X, Buffer=0x%p\n", InjectionInfo->TargetPid, InjectionInfo->DllBuffer);
				break;
			}
			Status = (NTSTATUS)Injector::Run((HANDLE)InjectionInfo->TargetPid, InjectionInfo->DllBuffer);
			break;
		}
		default:
			LOG("[*] Unknown IOCTL: 0x%X\n", controlCode);
			break;
	}
	
	Irp->IoStatus.Status = Status;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

EXTERN_C NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
)
{
	UNREFERENCED_PARAMETER(RegistryPath);
	NTSTATUS status = STATUS_SUCCESS;
	ExInitializeRundownProtection(&PendingOperations);


	RtlInitUnicodeString(&deviceName, DeviceName);
	RtlInitUnicodeString(&symLinkName, DosDeviceName);

	UNICODE_STRING ssdl;
	RtlInitUnicodeString(&ssdl, s_SDDL_DEVOBJ_SYS_ALL_ADM_RWX_WORLD_R);
	status = IoCreateDeviceSecure(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &ssdl, NULL, &DeviceObject);
	if (!NT_SUCCESS(status))
	{
		LOG("[*] Failed to create device  (status = %lx)\n", status);
		return status;
	}

	status = IoCreateSymbolicLink(&symLinkName, &deviceName);
	if (!NT_SUCCESS(status))
	{
		LOG("[*] Failed to create symlink  (status = %lx)\n", status);
		return status;
	}

	DriverObject->DriverUnload = DriverUnload;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = MJCreateCloseDispatch;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = MJCreateCloseDispatch;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControlHandler;

	LOG("[*] KMInjector Entry Point Executed!\n");
	return status;
}
