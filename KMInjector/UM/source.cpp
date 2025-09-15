#include <Windows.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <fstream>

#define IOCTL_INJECTOR_RUN							CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define DeviceName									L"\\\\.\\KMInjector"

typedef struct _INJECTION_INFO
{
	ULONG TargetPid;
	void* DllBuffer;
}INJECTION_INFO, * PINJECTION_INFO;

std::vector<uint8_t> ReadFile(const std::string filename)
{
	std::ifstream stream(filename, std::ios::binary);
	std::vector<uint8_t> buffer{ };
	buffer.assign((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());
	stream.close();
	return buffer;
}

int main(int argc, char* argv[]) {
	if (!argv[1] || !argv[2]) {
		printf("Usage: %s <PID> <Path to DLL>\n", argv[0]);
		return 1;
	}

	DWORD pid = atoi(argv[1]);
	HANDLE hDevice = CreateFile(DeviceName, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
	if (hDevice == INVALID_HANDLE_VALUE) {
		printf("Failed to open device. Error: %lu\n", GetLastError());
		return 1;
	}

	auto fileBuffer = ReadFile(argv[2]);
	if (fileBuffer.empty()) {
		printf("Failed to read file or file is empty.\n");
		CloseHandle(hDevice);
		return 1;
	}

	_INJECTION_INFO info;
	info.TargetPid = pid;
	info.DllBuffer = fileBuffer.data();

	DWORD bytesReturned;
	BOOL result = DeviceIoControl(hDevice, IOCTL_INJECTOR_RUN, &info, sizeof(_INJECTION_INFO), NULL, 0, &bytesReturned, NULL);
	if (!result) {
		printf("DeviceIoControl failed. Error: %lu\n", GetLastError());
		CloseHandle(hDevice);
		return 1;
	}
	printf("IOCTL sent successfully to inject into PID %lu\n", pid);
	CloseHandle(hDevice);
	return 0;
}