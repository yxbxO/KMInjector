# KMInjector
Kernel-mode DLL injection using direct PE mapping and `RtlCreateUserThread`. Bypasses user-mode detection by operating entirely in kernel space.

## Quick Start
```cmd
# Enable test signing
bcdedit /set testsigning on
# Restart required

# Install and start driver
sc create KMInjector type= kernel binPath= "C:\path\to\KMInjector.sys"
sc start KMInjector

# Inject DLL
UM.exe <pid> <dll_path>
```

## Example: Successful Injection into Notepad

![Successful Injection Demo](KMInjector/2025-09-15%2014_39_54-Window.png)

**Command:**
```cmd
UM.exe 5636 ExampleDLL.dll
```

**Result:** All 6 PE sections mapped successfully, thread created and executed in target process.

## How it works
1. **PE Analysis**: Parses the DLL's PE headers to extract entry point and image size
2. **Process Attachment**: Uses `KeAttachProcess` to attach to the target process address space (CR3)
3. **Memory Allocation**: Allocates executable memory in target process using `ZwAllocateVirtualMemory` with PAGE_EXECUTE_READWRITE permissions
4. **Image Relocation**: Relocates the PE image to the allocated memory address using proper base relocation
5. **Section Mapping**: Maps all PE sections (code, data, etc.) to the target process using `MmCopyVirtualMemory`
6. **Thread Creation**: Creates a new thread in the target process using `RtlCreateUserThread` pointing directly to the DLL's entry point
7. **Execution Monitoring**: Waits for thread completion with a 15-second timeout to ensure DLL initialization completes

## Important Limitations
⚠️ **CRITICAL**: This injection method does NOT handle import resolution or DLL initialization routines. The target DLL must meet specific requirements:

- **No Import Dependencies**: DLL must not import any external functions (kernel32.dll, ntdll.dll, etc.)
- **Custom Entry Point**: Must have a custom entry point that doesn't rely on standard DLL initialization
- **Self-Contained**: All functionality must be implemented using only the code within the DLL
- **No CRT Dependencies**: Cannot use C Runtime Library or other standard libraries

## Key Features
- **Direct PE Loading**: Maps the entire PE image without using LoadLibrary APIs
- **Manual Relocation**: Handles base relocations manually for proper execution
- **Thread-based Execution**: Uses RtlCreateUserThread for clean DLL initialization
- **Timeout Protection**: Prevents hanging with configurable thread timeout
- **Comprehensive Logging**: Detailed logging for debugging and monitoring

## Creating Compatible DLLs

Since import resolution is not handled, DLLs must be created with specific constraints:

### Example DLL Structure
```cpp
// Custom entry point - no standard DLL initialization
extern "C" __declspec(dllexport) void CustomEntryPoint(void* dllBase) {
    // Your code here - must be self-contained
    // No calls to external APIs (MessageBox, printf, etc.)
    // Use only inline assembly or direct system calls if needed
}

// Set custom entry point in linker settings
// /ENTRY:CustomEntryPoint
```

### Compiler/Linker Settings
- **Entry Point**: Set custom entry point (`/ENTRY:CustomEntryPoint`)
- **No Default Libraries**: Use `/NODEFAULTLIB` to avoid CRT dependencies
- **Manual Imports**: Avoid any `#include` statements that pull in external dependencies
- **Static Linking**: All code must be statically linked within the DLL

### Project Structure
- **KM/**: Kernel-mode driver (KMInjector.sys)
- **UM/**: User-mode application (UM.exe) 
- **ExampleDLL/**: Sample DLL demonstrating proper structure (no imports, custom entry point, manual API resolution)

### Current ExampleDLL Features
The included ExampleDLL demonstrates the correct approach:
- **Manual API Resolution**: Uses `GetExport()` and `GetModBase()` to find APIs at runtime
- **No Import Table**: Built without any import dependencies
- **Custom Entry Point**: `CustomDllMain()` function serves as the entry point
- **PEB Walking**: Uses Process Environment Block to locate loaded modules
- **Self-Contained**: All string functions (`__StrCmp`, `__WcsLen`, etc.) are implemented internally

## Building
1. Open `KMInjector.sln` in Visual Studio
2. Build the solution in Release mode for x64
3. The output files will be in `x64/Release/`

## Installation
1. Enable Test Signing: `bcdedit /set testsigning on`
2. Install the driver: `sc create KMInjector type= kernel binPath= C:\path\to\KMInjector.sys`
3. Start the driver: `sc start KMInjector`

## Detection Vectors and Considerations
- **Memory Scanning**: The injected DLL resides in executable memory that can be scanned for known patterns
- **PEB Walking**: Anti-cheat systems can enumerate loaded modules via PEB to detect unknown DLLs
- **Thread Creation Monitoring**: Systems monitoring thread creation APIs can detect the injection
- **Memory Permissions**: PAGE_EXECUTE_READWRITE allocations are suspicious and can be flagged
- **Driver Signing**: Requires test signing mode or proper code signing certificate
- **Process Handle Access**: Requires elevated privileges to open target processes

## Security Notes
- This tool is for educational and research purposes only
- Use only on systems you own or have explicit permission to test
- Some antivirus software may flag this as malicious due to its injection capabilities
- Consider the legal implications of DLL injection in your jurisdiction

## Technical Details
- Uses undocumented Windows APIs (`MmCopyVirtualMemory`, `RtlCreateUserThread`)
- Implements manual PE relocation handling
- Supports both 32-bit and 64-bit target processes (when built for x64)
- Thread timeout prevents infinite waiting during DLL initialization

## Why No Import Resolution?
This injection method operates entirely in kernel mode and bypasses the normal Windows DLL loading process:

- **No LoadLibrary**: Standard DLL loading APIs are not available in kernel mode
- **No Import Table Processing**: Windows normally resolves imports during LoadLibrary, but this step is skipped
- **Direct Memory Mapping**: The PE image is mapped directly without going through the Windows loader
- **Manual Relocation Only**: Only base relocations are handled; import resolution must be done manually

This approach provides stealth benefits but requires DLLs to be completely self-contained or implement their own API resolution mechanisms.
