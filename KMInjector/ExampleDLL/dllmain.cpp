#include <windows.h>
#include <winternl.h>

int __StrCmp(const char* S1, const char* S2) {
    if (!S1 || !S2) {
        return S1 ? 1 : (S2 ? -1 : 0);
    }

    unsigned char C1, C2;
    do {
        C1 = *S1++;
        C2 = *S2++;
        if (C1 == '\0')
            return C1 - C2;
    } while (C1 == C2);
    return C1 - C2;
}

int __WcsLen(wchar_t* Str)
{
    int Counter = 0;
    if (!Str)
        return 0;
    for (; *Str != '\0'; ++Str)
        ++Counter;
    return Counter;
}

int __WcsICmp(wchar_t* Cs, wchar_t* Ct)
{
    auto LenCs = __WcsLen(Cs);
    auto LenCt = __WcsLen(Ct);

    if (LenCs < LenCt)
        return false;

    for (size_t i = 0; i <= LenCs - LenCt; i++)
    {
        bool Match = true;

        for (size_t j = 0; j < LenCt; j++)
        {
            wchar_t CsChar = (Cs[i + j] >= L'A' && Cs[i + j] <= L'Z') ? (Cs[i + j] + L'a' - L'A') : Cs[i + j];
            wchar_t CtChar = (Ct[j] >= L'A' && Ct[j] <= L'Z') ? (Ct[j] + L'a' - L'A') : Ct[j];

            if (CsChar != CtChar)
            {
                Match = false;
                break;
            }
        }

        if (Match)
            return true;
    }

    return false;
}

void* GetExport(void* MBase, const char* SymbolName) {
    if (!MBase || !SymbolName) {
        return nullptr;
    }

    auto* Dos = (IMAGE_DOS_HEADER*)MBase;
    auto* Nt = (IMAGE_NT_HEADERS*)((char*)MBase + Dos->e_lfanew);
    auto* Exports = (IMAGE_EXPORT_DIRECTORY*)((char*)MBase +
        Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    auto* Names = (DWORD*)((char*)MBase + Exports->AddressOfNames);
    auto* Ordinals = (WORD*)((char*)MBase + Exports->AddressOfNameOrdinals);
    auto* Functions = (DWORD*)((char*)MBase + Exports->AddressOfFunctions);

    for (DWORD i = 0; i < Exports->NumberOfNames; i++) {
        char* FuncName = (char*)MBase + Names[i];
        if (!__StrCmp(FuncName, SymbolName)) {
            WORD Ordinal = Ordinals[i];
            return (char*)MBase + Functions[Ordinal];
        }
    }
    return nullptr;
}

void* GetModBase(const wchar_t* Name) {
    PPEB Peb = reinterpret_cast<PPEB>(__readgsqword(0x60));
    if (!Peb || !Peb->Ldr) return nullptr;

    if (Name == nullptr)
    {
        PLIST_ENTRY Entry = Peb->Ldr->InMemoryOrderModuleList.Flink;
        auto* Module = CONTAINING_RECORD(Entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        return Module->DllBase;
    }


    for (PLIST_ENTRY Entry = Peb->Ldr->InMemoryOrderModuleList.Flink;
        Entry != &Peb->Ldr->InMemoryOrderModuleList;
        Entry = Entry->Flink) {
        auto* Module = CONTAINING_RECORD(Entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        if (__WcsICmp(Module->FullDllName.Buffer, (wchar_t*)Name)) {
            return Module->DllBase;
        }
    }

    return nullptr;
}

void Init() {
    auto ModuleBase = GetModBase(L"USER32.dll");
    if (!ModuleBase)
        return;

    auto MessageBoxWFn = reinterpret_cast
        <int(*WINAPI)(
            HWND,
            LPCWSTR LpText,
            LPCWSTR LpCaption,
            UINT UType
            )>
        (GetExport(ModuleBase, "MessageBoxW"));


    if (!MessageBoxWFn)
        return;

    MessageBoxWFn(NULL, L"Extry Point Executed Successfully!", L"Success", MB_OK);
}

#pragma optimize( "", off ) 
BOOL APIENTRY CustomDllMain(
    HMODULE hModule
)
{
    Init();
    return TRUE;
}
#pragma optimize( "", on )
