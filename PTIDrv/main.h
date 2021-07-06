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

#pragma once
#include <ntddk.h>
#include <ntifs.h>

#define PTI_NT_DEVICE_NAME      L"\\Device\\PTIIO"
#define PTI_DOS_DEVICE_NAME     L"\\DosDevices\\PTIIO"

#define PTI_IOCTL_TYPE 40000

#define IOCTL_PTI_INJECT_PAYLOAD \
    CTL_CODE(PTI_IOCTL_TYPE, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define VIRTUAL_ADDRESS_BITS 48
#define VIRTUAL_ADDRESS_MASK ((((UINT64)1) << VIRTUAL_ADDRESS_BITS) - 1)

#define PML4_SHIFT 39
#define PTE_SHIFT 3
#define PML4_ENTRIES 512

#define PML4I_MASK (PML4_ENTRIES - 1)

#define PML4E(VirtAddr, PML4) \
	((((((UINT64)(VirtAddr) & VIRTUAL_ADDRESS_MASK) >> PML4_SHIFT) & PML4I_MASK) << PTE_SHIFT) + PML4)

typedef struct _PT_INJECT_PAYLOAD
{
    UINT32 TargetProcessId;
    UINT32 RemoteProcessId;
    ULONG64 RemotePayloadImageBase;
    ULONG64 PML4Index;
} PT_INJECT_PAYLOAD, * PPT_INJECT_PAYLOAD;

typedef union _VIRTUAL_ADDRESS
{
    PVOID Value;
    struct
    {
        ULONG64 Offset : 12;
        ULONG64 PtIndex : 9;
        ULONG64 PdIndex : 9;
        ULONG64 PdpIndex : 9;
        ULONG64 Pml4Index : 9;
        ULONG64 Reserved : 16;
    };
} VIRTUAL_ADDRESS, * PVIRTUAL_ADDRESS;

typedef union _PTE
{
    ULONG64 Value;
    struct
    {
        ULONG64 Present : 1;
        ULONG64 Writable : 1;
        ULONG64 UserAccess : 1;
        ULONG64 WriteThrough : 1;
        ULONG64 CacheDisabled : 1;
        ULONG64 Accessed : 1;
        ULONG64 Dirty : 1;
        ULONG64 AccessType : 1;
        ULONG64 Global : 1;
        ULONG64 Ignored_2 : 3;
        ULONG64 Pfn : 36;
        ULONG64 Reserved_1 : 4;
        ULONG64 Ignored_3 : 7;
        ULONG64 ProtectionKey : 4;
        ULONG64 ExecutionEisabled : 1;
    };
} PTE, * PPTE;