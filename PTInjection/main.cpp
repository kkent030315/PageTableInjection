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

#include <windows.h>
#include <iostream>

#include "types.hpp"
#include "nt.hpp"
#include "helper.hpp"
#include "pe.hpp"
#include "logger.hpp"

#define PTI_DEVICE_NAME "\\\\.\\PTIIO"
#define PTI_IOCTL_TYPE 40000
#define IOCTL_PTI_INJECT_PAYLOAD \
    CTL_CODE(PTI_IOCTL_TYPE, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _PT_INJECT_PAYLOAD
{
    UINT32 TargetProcessId;
    UINT32 RemoteProcessId;
    ULONG64 RemotePayloadImageBase;
    ULONG64 PML4Index;
} PT_INJECT_PAYLOAD, * PPT_INJECT_PAYLOAD;

static HANDLE device_handle = INVALID_HANDLE_VALUE;

bool initialize()
{
    device_handle = CreateFile(
        TEXT(PTI_DEVICE_NAME),        // file name
        GENERIC_READ | GENERIC_WRITE, // desired access
        0,             // share mode
        nullptr,       // security attributes
        OPEN_EXISTING, // creation disposition
        NULL,          // flags and attributes
        NULL);         // temp file handle

    if (device_handle == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    print_good("Device opened: 0x%lX\n", reinterpret_cast<u32>(device_handle));

    return true;
}

bool finalize_dispatch(PT_INJECT_PAYLOAD payload)
{
    DWORD bytes_returned;

    return DeviceIoControl(
        device_handle,
        IOCTL_PTI_INJECT_PAYLOAD,
        &payload, sizeof(PT_INJECT_PAYLOAD),
        &payload, sizeof(PT_INJECT_PAYLOAD),
        &bytes_returned,
        NULL);
}

HANDLE create_backing_process(HANDLE parent_process_handle)
{
    static auto procedure = 
        GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtCreateProcessEx");

    auto pNtCreateProcessEx = reinterpret_cast<NtCreateProcessEx>(procedure);

    HANDLE process_handle = 0;

    //
    // NtCreateProcessEx is the special API that usually don't gets called.
    // Calling this as the parameters below will create a empty
    // clone process of the parent (this process)
    // No threads will be created and no entry point will be called.
    //
    NTSTATUS nt_status = pNtCreateProcessEx(
        &process_handle,       // out process handle
        PROCESS_ALL_ACCESS,    // desired access
        NULL,                  // object attributes
        parent_process_handle, // parent process
        PS_INHERIT_HANDLES,    // flags
        NULL,                  // section handle
        NULL,                  // debug port
        NULL,                  // exception port
        FALSE);                // in job? (may obsolete)

    if (NT_SUCCESS(nt_status))
    {
        return process_handle;
    }

    return INVALID_HANDLE_VALUE;
}

void try_read_deployed_image(u64 deployment_va, u32 target_process_id)
{
    HANDLE target_process_handle =
        OpenProcess(PROCESS_VM_READ, FALSE, target_process_id);

    if (target_process_handle != INVALID_HANDLE_VALUE)
    {
        SIZE_T bytes_read = 0;
        USHORT dos_signature = 0;

        if (ReadProcessMemory(target_process_handle, (LPCVOID)deployment_va, &dos_signature, sizeof(USHORT), &bytes_read))
        {
            print_good("deployment dos signature: 0x%02X\n", dos_signature);
        }
    }
}

bool perform_inject(std::wstring dll_full_path, u32 target_process_id, u32 backing_process_id)
{
    PVOID mapped_image = NULL;
    std::vector<u8> file_buffer;
    SIZE_T written_size = 0;

    // use clone process of itself to backing the pml4e of the dll
    const bool use_clone_for_backing_process = backing_process_id == NULL;

    //
    // 1. Open handle for the backing process we create or specified
    //
    HANDLE backing_process_handle = 
        use_clone_for_backing_process ?
        create_backing_process(GetCurrentProcess()) :
        OpenProcess(PROCESS_ALL_ACCESS, FALSE, backing_process_id);

    if (use_clone_for_backing_process) backing_process_id = GetProcessId(backing_process_handle);

    if (backing_process_handle == INVALID_HANDLE_VALUE)
    {
        print_bad("Failed to open backing process handle\n");
        return false;
    }
    else
        print_good("Backing process: %d\n", backing_process_id);

    if (!copy_file_to_buffer(dll_full_path, file_buffer))
    {
        print_bad("Failed to create file buffer\n");
        return false;
    }

    const size_t image_size = PeLdrImageSize(file_buffer.data());

    //
    // 2. Allocate buffer for payload on the backing process
    //    
    //    Note that if this buffer is freed and the target
    //    process try to access memory region we deployed,
    //    it would cause MEMORY_MANAGEMENT bugcheck or critical system crash.
    //
    PVOID remote_image_base = VirtualAllocEx(
        backing_process_handle,
        NULL,
        image_size,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_EXECUTE_READWRITE);

    if (!remote_image_base)
    {
        print_bad("Failed to allocate memory on the backing process\n");
        return false;
    }
    else
        print_good("Buffer allocated on the backing process: 0x%p\n", remote_image_base);

    // Fix sections
    mapped_image = PeLdrMapImage(file_buffer.data(), file_buffer.size());
    if (!mapped_image)
    {
        print_bad("Failed to map image\n");
        return false;
    }

    // Relocate image
    PeLdrApplyImageRelocations(mapped_image, (u64)remote_image_base);
    print_info("Mapped image dos signature: 0x%02X\n", mapped_image);

    //
    // 3. Once we finished preparing PE,
    //    send the payload to the backing process
    //
    if (WriteProcessMemory(
        backing_process_handle,
        remote_image_base,
        mapped_image,
        image_size,
        &written_size) == FALSE)
    {
        print_bad("Failed to write image payload to the backing process (0x%lX) (0x%lX)\n", GetLastError(), written_size);
        VirtualFree(mapped_image, 0, MEM_RELEASE);
        return false;
    }
    else
        print_good("The payload has been sent\n");

    PT_INJECT_PAYLOAD payload = { 0 };
    payload.TargetProcessId = target_process_id;
    payload.RemoteProcessId = backing_process_id;
    payload.RemotePayloadImageBase = (u64)remote_image_base;
    payload.PML4Index = 221;

    //
    // 4. Manipulate PT to make specific PML4 entry of target process's will
    //    points to the backing process's PML4 entry that we allocated.
    //
    if (!finalize_dispatch(payload))
    {
        print_bad("Failed to finalize payload (0x%lX)\n", GetLastError());
        VirtualFree(mapped_image, 0, MEM_RELEASE);
        return false;
    }

    // The virtual memory on the deployment location of the target process 
    VIRTUAL_ADDRESS deployment_va = { remote_image_base };
    deployment_va.Pml4Index = payload.PML4Index;

    print_info("Payload is now mapped to the target process VA: 0x%llX\n", deployment_va.Value);

    try_read_deployed_image((u64)deployment_va.Value, target_process_id);

    VirtualFree(mapped_image, 0, MEM_RELEASE);
    return true;
}

int wmain(int argc, const wchar_t** argv, const wchar_t** envp)
{
    print_info("PageTable Injection\n");

    if (argc < 3)
    {
        print_info("Usage: [target pid] [dll path] [backing process pid(optional)]\n");
        print_info("     -          target pid: The target process to inject\n");
        print_info("     -            dll path: Full path to the desired dll\n");
        print_info("     - backing process pid: The process backing the pml4 entry of the dll\n");
        return EXIT_FAILURE;
    }
    
    const auto target_process_id = _wtoi(argv[1]);
    const auto dll_full_path = std::wstring(argv[2]);
    const auto backing_process_id = argc >= 4 ? _wtoi(argv[3]) : NULL;

    if (!initialize())
    {
        print_bad("Failed to initialize\n");
        return EXIT_FAILURE;
    }

    if (!perform_inject(dll_full_path, target_process_id, backing_process_id))
    {
        print_bad("Failed to perform inject\n");
        return EXIT_FAILURE;
    }

    print_info("Done\n");
    return EXIT_SUCCESS;
}
