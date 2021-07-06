/*

    MIT License

    Copyright (c) 2021 Kento Oki

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.

*/

#include "main.h"

//
// After 1709 we can't use MmMapIoSpace to map PTs.
// Thus we have to map it.
//
NTSTATUS MapPhysicalMemoryForIoSpace(
    OUT PUINT_PTR VirtualAddress,
    IN UINT_PTR PhysicalAddress,
    IN SIZE_T Size)
{
    NTSTATUS ntStatus = STATUS_SUCCESS;
    UNICODE_STRING ObjectNameUs;
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE SectionHandle;
    PVOID Object;
    ULONG BusAddressSpace;
    PHYSICAL_ADDRESS PhysicalAddressStart;
    PHYSICAL_ADDRESS PhysicalAddressEnd;
    PHYSICAL_ADDRESS ViewBase;
    BOOLEAN HalTranslateResult1, HalTranslateResult2;
    PUCHAR pBaseAddress = NULL;

    *VirtualAddress = 0;

    PHYSICAL_ADDRESS _PhysicalAddress;
    _PhysicalAddress.QuadPart = PhysicalAddress;

    RtlInitUnicodeString(&ObjectNameUs, L"\\Device\\PhysicalMemory");

    InitializeObjectAttributes(&ObjectAttributes,
        &ObjectNameUs,
        OBJ_CASE_INSENSITIVE,
        (HANDLE)NULL,
        (PSECURITY_DESCRIPTOR)NULL);

    ntStatus = ZwOpenSection(
        &SectionHandle, SECTION_ALL_ACCESS, &ObjectAttributes);

    if (!NT_SUCCESS(ntStatus))
    {
        return ntStatus;
    }

    ntStatus = ObReferenceObjectByHandle(
        SectionHandle,
        SECTION_ALL_ACCESS,
        (POBJECT_TYPE)NULL,
        KernelMode,
        &Object,
        (POBJECT_HANDLE_INFORMATION)NULL);

    if (!NT_SUCCESS(ntStatus))
    {
        ZwClose(SectionHandle);
        return ntStatus;
    }

    PhysicalAddressStart.QuadPart = (ULONGLONG)(ULONG_PTR)PhysicalAddress;
    PhysicalAddressEnd.QuadPart = PhysicalAddressStart.QuadPart + Size;

    BusAddressSpace = 0;
    HalTranslateResult1 =
        HalTranslateBusAddress(0, 0, PhysicalAddressStart, &BusAddressSpace, &PhysicalAddressStart);

    BusAddressSpace = 0;
    HalTranslateResult2 =
        HalTranslateBusAddress(0, 0, PhysicalAddressEnd, &BusAddressSpace, &PhysicalAddressEnd);

    if (!HalTranslateResult1 || !HalTranslateResult2)
    {
        ZwClose(SectionHandle);
        return STATUS_UNSUCCESSFUL;
    }

    Size = (SIZE_T)PhysicalAddressEnd.QuadPart - (SIZE_T)PhysicalAddressStart.QuadPart;
    ViewBase = PhysicalAddressStart;

    ntStatus = ZwMapViewOfSection(
        SectionHandle,
        NtCurrentProcess(),
        &pBaseAddress,
        0L,
        Size,
        &ViewBase,
        &Size,
        ViewShare,
        0,
        PAGE_READWRITE | PAGE_NOCACHE);

    if (!NT_SUCCESS(ntStatus))
    {
        ZwClose(SectionHandle);
        return ntStatus;
    }

    pBaseAddress += PhysicalAddressStart.QuadPart - ViewBase.QuadPart;
    *VirtualAddress = pBaseAddress;

    ZwClose(SectionHandle);
    return ntStatus;
}

NTSTATUS UnmapPhysicalMemoryForIoSpace(IN UINT_PTR VirtualAddress)
{
    return ZwUnmapViewOfSection(NtCurrentProcess(), VirtualAddress);
}

NTSTATUS InjectPayloadToProcessPte(PPT_INJECT_PAYLOAD Payload)
{
    NTSTATUS ntStatus = STATUS_SUCCESS;
    PEPROCESS TargetProcess = NULL;
    PEPROCESS BackingProcess = NULL;
    PVOID DirBaseTarget = NULL, DirBaseBacking = NULL;
    PHYSICAL_ADDRESS PhysAddrTargetDirBase = { 0 }, PhysAddrRemoteDirBase = { 0 };
    PVOID IoSpace = NULL;
    VIRTUAL_ADDRESS RemoteImageVa = { Payload->RemotePayloadImageBase };
    PHYSICAL_ADDRESS DeploymentLocation = { 0 };
    PHYSICAL_ADDRESS PhysBackedPml4EntryAddr = { 0 };
    MM_COPY_ADDRESS SourceAddress = { 0 };
    ULONG64 PML4Entry = 0;
    SIZE_T NumberOfBytesTransferred = 0;

    DbgPrint("Payload->TargetProcessId: %d\n", Payload->TargetProcessId);
    DbgPrint("Payload->RemoteProcessId: %d\n", Payload->RemoteProcessId);
    DbgPrint("Payload->RemotePayloadImageBase: 0x%llX (PML4Index: 0x%llX)\n", Payload->RemotePayloadImageBase, Payload->PML4Index);
    DbgPrint("Payload->PML4Index: %d\n", (UINT32)(Payload->PML4Index));

    if (!NT_SUCCESS(ntStatus = PsLookupProcessByProcessId((HANDLE)Payload->TargetProcessId, &TargetProcess)))
    {
        DbgPrint("Failed to lookup TargetProcess\n");
        return ntStatus;
    }

    if (!NT_SUCCESS(ntStatus = PsLookupProcessByProcessId((HANDLE)Payload->RemoteProcessId, &BackingProcess)))
    {
        DbgPrint("Failed to lookup BackingProcess\n");
        return ntStatus;
    }

    //
    // 1. Locate certain PML4 base.
    //
    //1: kd> dt nt!_KPROCESS DirectoryTableBase
    //   + 0x028 DirectoryTableBase : Uint8B
    //
    DirBaseTarget = (*(PTE*)((ULONG64)TargetProcess + 0x28)).Pfn << PAGE_SHIFT;
    DirBaseBacking = (*(PTE*)((ULONG64)BackingProcess + 0x28)).Pfn << PAGE_SHIFT;

    DbgPrint("BackingProcess: 0x%p (DirBase: 0x%llX)\n", BackingProcess, DirBaseBacking);
    DbgPrint("TargetProcess: 0x%p (DirBase: 0x%llX)\n", TargetProcess, DirBaseTarget);

    //
    // 2. Locate the PML4 entries for both backing page and deployment location.
    //
    PhysAddrTargetDirBase.QuadPart = (ULONG64)DirBaseTarget + Payload->PML4Index;
    PhysAddrRemoteDirBase.QuadPart = (ULONG64)DirBaseBacking + RemoteImageVa.Pml4Index;

    //
    // 3. Copy PML4 entry of backing page to our temprary buffer.
    //
    PhysBackedPml4EntryAddr.QuadPart = PML4E(Payload->RemotePayloadImageBase, (UINT_PTR)DirBaseBacking);
    SourceAddress.PhysicalAddress = PhysBackedPml4EntryAddr;
    if (!NT_SUCCESS(ntStatus = MmCopyMemory(&PML4Entry, SourceAddress, sizeof(ULONG64), MM_COPY_MEMORY_PHYSICAL, &NumberOfBytesTransferred)))
    {
        DbgPrint("Failed to copy backing process's image base pml4e\n");
        return ntStatus;
    }

    DbgPrint("(0x%lX) Backing process payload dll pml4e: 0x%llX\n", NumberOfBytesTransferred, PML4Entry);

    // This will be the virtual address of deployment location on the target process.
    VIRTUAL_ADDRESS DeploymentVa = { Payload->RemotePayloadImageBase };
    DeploymentVa.Pml4Index = Payload->PML4Index; // New PML4 index.

    //
    // 4. Map the deployment location of the PML4 entry to our buffer
    //
    if (!NT_SUCCESS(ntStatus = MapPhysicalMemoryForIoSpace(&IoSpace, PML4E(DeploymentVa.Value, (UINT_PTR)DirBaseTarget), sizeof(PVOID))))
    {
        DbgPrint("Failed to map I/O space for phys: 0x%llX\n", PhysAddrTargetDirBase.QuadPart);
        return ntStatus;
    }

    DbgPrint("I/O space 0x%p is mapped for phys: 0x%llX\n", IoSpace, PhysAddrTargetDirBase.QuadPart);

    //
    // 5. Deploy it!
    //
    DbgPrint("Deploying PML4 entry to [0x%llX]...\n", *(ULONG64*)(IoSpace));
    *(ULONG64*)(IoSpace) = PML4Entry;
    DbgPrint("Deployed: 0x%llX\n", *(ULONG64*)(IoSpace));

    DbgPrint("Deployed to the target process VA: 0x%llX\n", DeploymentVa.Value);

    UnmapPhysicalMemoryForIoSpace(IoSpace);
    return ntStatus;
}

VOID UnloadDriver(IN PDRIVER_OBJECT DriverObject)
{
    PDEVICE_OBJECT DeviceObject = DriverObject->DeviceObject;
    UNICODE_STRING DosDeviceNameUs;

    RtlInitUnicodeString(&DosDeviceNameUs, PTI_DOS_DEVICE_NAME);
    IoDeleteSymbolicLink(&DosDeviceNameUs);

    if (DeviceObject != NULL)
    {
        IoDeleteDevice(DeviceObject);
    }
}

NTSTATUS CreateClose(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PAGED_CODE();

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS DeviceIoControl(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp)
{
    NTSTATUS ntStatus = STATUS_SUCCESS;
    PIO_STACK_LOCATION IrpSp;
    ULONG InBufLength;
    ULONG OutBufLength;
    PVOID InputBuffer = NULL, OutputBuffer = NULL;

    UNREFERENCED_PARAMETER(DeviceObject);

    PAGED_CODE();

    DbgPrint("Irp\n");

    IrpSp = IoGetCurrentIrpStackLocation(Irp);
    InBufLength = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
    OutBufLength = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;

    if (!InBufLength || !OutBufLength)
    {
        ntStatus = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    InputBuffer = Irp->AssociatedIrp.SystemBuffer;
    OutputBuffer = Irp->AssociatedIrp.SystemBuffer;

    switch (IrpSp->Parameters.DeviceIoControl.IoControlCode)
    {
    case IOCTL_PTI_INJECT_PAYLOAD:
    {
        PT_INJECT_PAYLOAD Payload = *(PT_INJECT_PAYLOAD*)InputBuffer;

        if (!NT_SUCCESS(ntStatus = InjectPayloadToProcessPte(&Payload)))
        {
            DbgPrint("Failed to execute PTE injection (0x%lX)\n", ntStatus);
        }

        Irp->IoStatus.Information = 1;
        break;
    }
    }

Exit:
    Irp->IoStatus.Status = ntStatus;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return ntStatus;
}

NTSTATUS DispatchDriverEntry(
    IN PDRIVER_OBJECT DriverObject,
    IN PUNICODE_STRING RegistryPath)
{
    NTSTATUS ntStatus = STATUS_SUCCESS;
    UNICODE_STRING  NtDeviceNameUs;
    UNICODE_STRING  DosDeviceNameUs;
    PDEVICE_OBJECT  DeviceObject = NULL;

    RtlInitUnicodeString(&NtDeviceNameUs, PTI_NT_DEVICE_NAME);

    ntStatus = IoCreateDevice(
        DriverObject,            // our driver object
        0,                       // we don't use a device extension
        &NtDeviceNameUs,         // device name
        FILE_DEVICE_UNKNOWN,     // device type
        FILE_DEVICE_SECURE_OPEN, // device characteristics
        FALSE,                   // not an exclusive device
        &DeviceObject);          // returned pointer to Device Object

    if (!NT_SUCCESS(ntStatus))
    {
        return ntStatus;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = CreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = CreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceIoControl;
    DriverObject->DriverUnload = UnloadDriver;

    RtlInitUnicodeString(&DosDeviceNameUs, PTI_DOS_DEVICE_NAME);

    ntStatus = IoCreateSymbolicLink(&DosDeviceNameUs, &NtDeviceNameUs);

    if (!NT_SUCCESS(ntStatus))
    {
        IoDeleteDevice(DeviceObject);
    }

    return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(
    IN PDRIVER_OBJECT DriverObject,
    IN PUNICODE_STRING RegistryPath)
{
    return DispatchDriverEntry(DriverObject, RegistryPath);
}