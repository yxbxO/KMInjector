#include "stdafx.h"
namespace Injector {
    IMAGE_NT_HEADERS* GetNTHeaders(uintptr_t ImageBase) {
        if (!ImageBase) {
            LOG("[*] Invalid Image Base Address\n");
            return nullptr;
        }

        const auto DosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(ImageBase);
        if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            LOG("[*] Invalid DOS Signature\n");
            return nullptr;
        }

        IMAGE_NT_HEADERS* Ret = (IMAGE_NT_HEADERS*)(ImageBase + DosHeader->e_lfanew);
        if (Ret->Signature != IMAGE_NT_SIGNATURE) {
            LOG("[*] Invalid NT Signature\n");
            return NULL;
        }

        return Ret;
    }

    void* RvaToVa(const uintptr_t Rva, IMAGE_NT_HEADERS* NtHeader, void* LocalImage) {
        if (!NtHeader || !LocalImage) {
            return nullptr;
        }

        const auto FirstSection = IMAGE_FIRST_SECTION(NtHeader);
        for (auto Section = FirstSection; Section < FirstSection + NtHeader->FileHeader.NumberOfSections; Section++) {
            if (Rva >= Section->VirtualAddress && Rva < Section->VirtualAddress + Section->Misc.VirtualSize) {
                return static_cast<unsigned char*>(LocalImage) + Section->PointerToRawData + (Rva - Section->VirtualAddress);
            }
        }
        return nullptr;
    }

    bool RelocateImage(void* RemoteImage, void* LocalImage, IMAGE_NT_HEADERS* NtHeader) {
        struct RelocEntry {
            ULONG to_rva;
            ULONG size;
            struct {
                WORD offset : 12;
                WORD type : 4;
            } item[1];
        };

        if (!RemoteImage || !LocalImage || !NtHeader) {
            return false;
        }

        const uintptr_t DeltaOffset = reinterpret_cast<uintptr_t>(RemoteImage) - NtHeader->OptionalHeader.ImageBase;
        if (DeltaOffset == 0) {
            return true;
        }

        if ((NtHeader->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) == 0) {
            return false;
        }

        const auto& RelocDir = NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (RelocDir.VirtualAddress == 0 || RelocDir.Size == 0) {
            return true;
        }

        auto* RelocationEntry = reinterpret_cast<RelocEntry*>(
            RvaToVa(RelocDir.VirtualAddress, NtHeader, LocalImage)
        );
        if (!RelocationEntry) {
            return true;
        }

        const uintptr_t RelocationEnd = reinterpret_cast<uintptr_t>(RelocationEntry) + RelocDir.Size;

        while (reinterpret_cast<uintptr_t>(RelocationEntry) < RelocationEnd && RelocationEntry->size) {
            const size_t RecordsCount = (RelocationEntry->size - sizeof(RelocEntry) + sizeof(WORD)) / sizeof(WORD);

            for (size_t i = 0; i < RecordsCount; ++i) {
                const WORD Type = RelocationEntry->item[i].type;
                const WORD Offset = RelocationEntry->item[i].offset;
                if (Type == IMAGE_REL_BASED_ABSOLUTE) {
                    continue;
                }

                if (Type == IMAGE_REL_BASED_HIGHLOW || Type == IMAGE_REL_BASED_DIR64) {
                    auto* FixupAddr = static_cast<unsigned char*>(
                        RvaToVa(RelocationEntry->to_rva, NtHeader, LocalImage)
                    );
                    if (!FixupAddr) {
                        FixupAddr = static_cast<unsigned char*>(LocalImage);
                    }
                    auto* PatchAddr = reinterpret_cast<uintptr_t*>(FixupAddr + (Offset % 0x1000));
                    *PatchAddr += DeltaOffset;
                }
            }

            RelocationEntry = reinterpret_cast<RelocEntry*>(
                reinterpret_cast<unsigned char*>(RelocationEntry) + RelocationEntry->size
            );
        }

        return true;
    }

    bool MapSections(PEPROCESS PProcess, PEPROCESS TargetProcess, void* ModuleBase, void* LocalImage, IMAGE_NT_HEADERS* NtHeader) {
        auto Section = IMAGE_FIRST_SECTION(NtHeader);
        auto NumSections = NtHeader->FileHeader.NumberOfSections;
        LOG("[*] Number Of Sections To Map: %u\n", NumSections);

        for (WORD SectionCount = 0; SectionCount < NumSections; SectionCount++, Section++) {

            auto DestAddress = (DWORD64)((uintptr_t)ModuleBase + Section->VirtualAddress);
            auto SourceAddress = (PVOID)((uintptr_t)LocalImage + Section->PointerToRawData);
            auto Size = Section->SizeOfRawData;
            if (!Size)
                continue;

            //if (
            //    !strcmp(reinterpret_cast<char*>(Section->Name), (".reloc"))
            //    || !strcmp(reinterpret_cast<char*>(Section->Name), (".rsrc"))
            //    )
            //{
            //    LOG("[*] Skipping Section %u (%s)", SectionCount + 1, (char*)Section->Name);
            //    continue;
            //}

            LOG("[*] Mapping Section %u (%s)\n", SectionCount + 1, (char*)Section->Name);

            SIZE_T CleanupBytesWritten = 0;
            auto WriteStatus = MmCopyVirtualMemory(
                PProcess,
                SourceAddress,
                TargetProcess,
                (PVOID)DestAddress,
                Size,
                KernelMode,
                &CleanupBytesWritten
            );

            if (!NT_SUCCESS(WriteStatus)) {
                LOG("[*] Map Failed At Address 0x%p, Size %u Bytes\n", (void*)DestAddress, Size);
                return false;
            }

            LOG("[*] Destination: 0x%p, Source: 0x%p, Size: %u Bytes | %i |\n", (void*)DestAddress, SourceAddress, Size, (int)WriteStatus);
        }

        LOG("[*] Successfully Mapped All %u Sections\n", NumSections);
        return true;
    }

    auto ExecEntryPointSimple(HANDLE TargetPid, void* AllocBase, unsigned long EntryPoint) -> BOOL {
        LOG("[*] Execute DLL Via Simple RtlCreateUserThread Method Called\n");
        LOG("[*] DLL Base: 0x%p, Entry Point RVA: 0x%X, Full Entry Point: 0x%p\n",
            AllocBase, EntryPoint, (void*)((uintptr_t)AllocBase + EntryPoint));

        // Validate input parameters
        if (!AllocBase || !EntryPoint || !TargetPid) {
            LOG("[*] Invalid Parameters For DLL Execution\n");
            return 0;
        }

        // Get target process
        PEPROCESS TargetProcess = NULL;
        NTSTATUS Status = PsLookupProcessByProcessId(TargetPid, &TargetProcess);
        if (!NT_SUCCESS(Status)) {
            LOG("[*] Failed To Get Target Process\n");
            return 0;
        }

        // Open target process
        HANDLE ProcessHandle = nullptr;
        OBJECT_ATTRIBUTES ObjAttr = { 0 };
        CLIENT_ID ProcessClientId = { 0 };
        ProcessClientId.UniqueProcess = TargetPid;

        InitializeObjectAttributes(&ObjAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

        Status = ZwOpenProcess(&ProcessHandle, PROCESS_ALL_ACCESS, &ObjAttr, &ProcessClientId);
        if (!NT_SUCCESS(Status)) {
            LOG("[*] Failed To Open Target Process: 0x%X\n", Status);
            ObDereferenceObject(TargetProcess);
            return 0;
        }

        LOG("[*] Opened Target Process For Thread Creation\n");

        // Create thread using RtlCreateUserThread with the DLL entry point directly
        HANDLE ThreadHandle = nullptr;
        CLIENT_ID ThreadClientId = { 0 };

        Status = RtlCreateUserThread(
            ProcessHandle,             // Target process handle
            NULL,                       // Security descriptor
            FALSE,                      // Create suspended (FALSE = not suspended)
            0,                          // Stack zero bits
            0,                          // Stack reserved
            0,                          // Stack commit
            (PVOID)((char*)AllocBase + EntryPoint), // Start address (DLL entry point)
            (LPVOID)AllocBase,         // Start parameter (DLL base address)
            &ThreadHandle,
            &ThreadClientId
        );

        if (!NT_SUCCESS(Status)) {
            LOG("[*] RtlCreateUserThread Failed With Status: 0x%X\n", Status);
            ZwClose(ProcessHandle);
            ObDereferenceObject(TargetProcess);
            return 0;
        }

        LOG("[*] RtlCreateUserThread Succeeded, Thread Handle: 0x%p\n", ThreadHandle);

        // Wait for thread completion (with timeout)
        LARGE_INTEGER Timeout;
        Timeout.QuadPart = -150000000LL; // 15 seconds

        Status = ZwWaitForSingleObject(
            ThreadHandle,
            FALSE,
            &Timeout
        );

        if (Status == STATUS_TIMEOUT) {
            LOG("[*] Thread Execution Timed Out After 15 Seconds\n");
        }
        else if (NT_SUCCESS(Status)) {
            LOG("[*] Thread Execution Completed Successfully\n");
        }
        else {
            LOG("[*] Wait Failed With Status: 0x%X\n", Status);
        }

        // Clean up
        ZwClose(ThreadHandle);
        ZwClose(ProcessHandle);
        ObDereferenceObject(TargetProcess);

        LOG("[*] DLL Execution Via Simple RtlCreateUserThread Completed For PID: %p At Address: 0x%p\n", TargetPid, AllocBase);

        return 1;
    }

    int Run(HANDLE Pid, void* Buffer)
    {
        if (!Pid || !Buffer) {
            LOG("[*] Invalid Parameters: PID=0x%p, Buffer=0x%p\n", Pid, Buffer);
            return 1;
        }

        const auto NtHeader = GetNTHeaders((uintptr_t)Buffer);
        if (!NtHeader) {
            LOG("[*] Invalid NT Headers\n");
            return 1;
        }

        uintptr_t EntryPoint;
        EntryPoint = NtHeader->OptionalHeader.AddressOfEntryPoint;

        // Get target process
        PEPROCESS TargetProcess = NULL;
        NTSTATUS Status = PsLookupProcessByProcessId(Pid, &TargetProcess);
        if (!NT_SUCCESS(Status)) {
            LOG("[*] Failed To Get Target Process\n");
            return 2;
        }

        // Allocate shellcode remotely in target process using ZwAllocateVirtualMemory
        PVOID DllAllocBase = NULL;
        SIZE_T AllocationSize = NtHeader->OptionalHeader.SizeOfImage;
        KeAttachProcess(TargetProcess);
        Status = ZwAllocateVirtualMemory(NtCurrentProcess(), &DllAllocBase, 0, &AllocationSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        KeDetachProcess();

        if (!NT_SUCCESS(Status)) {
            LOG("[*] Failed To Allocate Remote Shellcode\n");
            ObDereferenceObject(TargetProcess);
            return 3;
        }

        if (!RelocateImage(DllAllocBase, (void*)Buffer, NtHeader)) {
            LOG("[*] Image Failed To Relocate\n");
            ObDereferenceObject(TargetProcess);
            return 4;
        }

        if (!MapSections(IoGetCurrentProcess(), TargetProcess, DllAllocBase, (void*)Buffer, NtHeader)) {
            LOG("[*] Failed To Map Sections\n");
            ObDereferenceObject(TargetProcess);
            return 5;
        }

        ObDereferenceObject(TargetProcess);

        // Use simple RtlCreateUserThread method instead of shellcode execution
        if (!ExecEntryPointSimple(Pid, DllAllocBase, NtHeader->OptionalHeader.AddressOfEntryPoint))
        {
            LOG("[*] Failed To Execute Entry Point Via Simple Method\n");
            return 6;
        }

        LOG("[*] DLL Injection Completed Successfully Via Simple RtlCreateUserThread Method\n");

        return 0;
    }

}