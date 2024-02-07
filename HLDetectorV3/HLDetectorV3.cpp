#include <Windows.h>
#include "hwbp_hook.hpp"
#include <cstdio>
#include <winternl.h>
#include <iostream>
#include <fstream>
#include "LazyImport.hpp"
#include "XorString.hpp"

#ifdef _DEBUG
#include <ntstatus.h>
#include <winternl.h>
#include <codecvt>
#include <locale>

#pragma comment(lib, "ntdll.lib")
typedef NTSTATUS(NTAPI* pfnNtOpenFile)(
	PHANDLE            FileHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK   IoStatusBlock,
	ULONG              ShareAccess,
	ULONG              OpenOptions
	);

typedef NTSTATUS(NTAPI* pfnNtReadFile)(
	HANDLE            FileHandle,
	HANDLE            Event,
	PIO_APC_ROUTINE   ApcRoutine,
	PVOID             ApcContext,
	PIO_STATUS_BLOCK  IoStatusBlock,
	PVOID             Buffer,
	ULONG             Length,
	PLARGE_INTEGER    ByteOffset,
	PULONG            Key
	);

extern "C" {
	NTSTATUS NTAPI RtlDosPathNameToNtPathName_U(
		PCWSTR DosPathName,
		PUNICODE_STRING NtPathName,
		PCWSTR* NtFileNamePart,
		PVOID* DirectoryInfo);
	VOID NTAPI RtlFreeUnicodeString(PUNICODE_STRING UnicodeString);
}


std::string WStringToString(const std::wstring& wstr) {
	std::string strTo;
	strTo.reserve(wstr.length());
	for (wchar_t wc : wstr) {
		strTo += static_cast<char>(wc); 
	}
	return strTo;
}

std::wstring GetExecutableFolderPath() {
	wchar_t path[MAX_PATH] = { 0 };

	if (GetModuleFileNameW(NULL, path, MAX_PATH) > 0) {
		std::wstring fullPath(path);
		size_t pos = fullPath.find_last_of(L"\\/");
		if (pos != std::wstring::npos) {
			return fullPath.substr(0, pos);
		}
	}
	return L"";
}

std::string wstringToString(const std::wstring& wstr) {
	if (wstr.empty()) {
		return std::string();
	}

	int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);
	std::string strTo(sizeNeeded, 0);
	WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &strTo[0], sizeNeeded, nullptr, nullptr);
	strTo.pop_back();
	return strTo;
}
void writeToLog(const std::string& text) {
	std::ofstream logFile("logs.txt", std::ios::app);
	if (logFile.is_open()) {
		logFile << text << std::endl;
		logFile.close();
	}
	else {
		std::cerr << "Unable to open logs.txt for writing." << std::endl;
	}
}
void writeToLog(const std::wstring& wtext) {
	writeToLog(wstringToString(wtext));
}
void writeToLogW(const std::string& text) {
	std::ofstream logFile("logWW.txt", std::ios::app);
	if (logFile.is_open()) {
		logFile << text << std::endl;
		logFile.close();
	}
	else {
		std::cerr << "Unable to open logs.txt for writing." << std::endl;
	}
}

void writeToLogW(const std::wstring& wtext) {
	writeToLog(wstringToString(wtext));
}
#endif
NTSTATUS NTAPI HookedNtOpenFile(
	PHANDLE FileHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK IoStatusBlock,
	ULONG ShareAccess,
	ULONG OpenOptions
) {
	if (ObjectAttributes != nullptr)
	{
		if (ObjectAttributes->ObjectName != nullptr && ObjectAttributes->ObjectName->Buffer != nullptr)
		{
#ifdef _DEBUG
			writeToLog(ObjectAttributes->ObjectName->Buffer);
#endif
			std::wstring a = XorStringW(L"\\data\\images\\");
			std::wstring b = XorStringW(L"\\data\\config\\");
			std::wstring c = XorStringW(L"HLBot");

			if ((std::wcsstr(ObjectAttributes->ObjectName->Buffer, a.c_str())) || (std::wcsstr(ObjectAttributes->ObjectName->Buffer, b.c_str()) || (std::wcsstr(ObjectAttributes->ObjectName->Buffer, c.c_str()))))
			{
#ifdef _DEBUG
				writeToLog(ObjectAttributes->ObjectName->Buffer);
#endif
				LI_FN(ExitProcess)(0);
				LI_FN(__fastfail)(0);
			}
		}

	}
	return hook_manager::get()[XorString("NtOpenFile")]->call<NTSTATUS>(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions);
}


std::wstring GetFilePathFromHandle(HANDLE hFile) {
	TCHAR filePath[MAX_PATH] = { 0 };
	if (hFile == INVALID_HANDLE_VALUE)
		return L"";

	DWORD dwRet = GetFinalPathNameByHandleW(hFile, (LPWSTR)filePath, MAX_PATH, FILE_NAME_NORMALIZED);
	if (dwRet == 0) {
		return L"";
	}

	std::wstring path((LPWSTR)filePath);

	if (path.find(XorStringW(L"\\\\?\\")) == 0) {
		path = path.substr(4);
	}

	return path;
}
NTSTATUS NTAPI HookNtReadFile(
	HANDLE           FileHandle,
	HANDLE           Event,
	PIO_APC_ROUTINE  ApcRoutine,
	PVOID            ApcContext,
	PIO_STATUS_BLOCK IoStatusBlock,
	PVOID            Buffer,
	ULONG            Length,
	PLARGE_INTEGER   ByteOffset,
	PULONG           Key
) {

	std::wstring filePath = GetFilePathFromHandle(FileHandle);
	std::wstring a = XorStringW(L"\\data\\images\\");
	std::wstring b = XorStringW(L"\\data\\config\\");
	std::wstring c = XorStringW(L"HLBot");
	if ((std::wcsstr(filePath.c_str(), a.c_str())) || (std::wcsstr(filePath.c_str(), b.c_str()) || (std::wcsstr(filePath.c_str(), c.c_str()))))
	{

		LI_FN(ExitProcess)(0);
		LI_FN(__fastfail)(0);

	}
	return hook_manager::get()[XorString("NtReadFile")]->call<NTSTATUS>(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
}
struct ReadFileParams {
	std::wstring filePath;
	HANDLE fileHandle;
	HANDLE eventHandle;
	pfnNtReadFile NtReadFileFunc;
};

void InitHLDetv3() {
	auto NtOpenFileOff = LI_FN(GetProcAddress)(LI_FN(GetModuleHandleA)(XorString("ntdll.dll")), XorString("NtOpenFile"));
	auto NtReadFileOff = LI_FN(GetProcAddress)(LI_FN(GetModuleHandleA)(XorString("ntdll.dll")), XorString("NtReadFile"));
	auto& mgr = hook_manager::get();
	mgr.init();
	mgr[XorString("NtOpenFile")]->hook(NtOpenFileOff, HookedNtOpenFile);
	mgr[XorString("NtReadFile")]->hook(NtReadFileOff, HookNtReadFile);
}


DWORD WINAPI ReadFileThread(LPVOID lpParam) {
	ReadFileParams* params = static_cast<ReadFileParams*>(lpParam);
	if (!params) return 1;

	const ULONG bufferSize = 1024;
	char buffer[bufferSize] = { 0 };
	IO_STATUS_BLOCK ioStatus;
	LARGE_INTEGER offset = { 0 };

	NTSTATUS status = params->NtReadFileFunc(params->fileHandle, params->eventHandle, NULL, NULL, &ioStatus, buffer, bufferSize - 1, &offset, NULL);
	if (status == STATUS_PENDING) {
		WaitForSingleObject(params->eventHandle, INFINITE);
	}

	if (ioStatus.Status == STATUS_SUCCESS) {
		std::cout << "Contents of " << WStringToString(params->filePath) << ":\n";
		std::cout.write(buffer, ioStatus.Information);
		std::cout << "\n";
	}
	else {
		std::cerr << "Failed to read file " << WStringToString(params->filePath) << ". NTSTATUS Error code: 0x" << std::hex << ioStatus.Status << std::endl;
	}

	CloseHandle(params->eventHandle);
	CloseHandle(params->fileHandle);
	delete params;
	return 0;
}

int main() {
	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)InitHLDetv3, 0, 0, NULL);
	Sleep(1200);
	HMODULE hNtDll = GetModuleHandleA("ntdll.dll");
	if (!hNtDll) {
		std::cerr << "Failed to get ntdll.dll\n";
		return 1;
	}

	auto NtOpenFile = reinterpret_cast<pfnNtOpenFile>(GetProcAddress(hNtDll, "NtOpenFile"));
	auto NtReadFile = reinterpret_cast<pfnNtReadFile>(GetProcAddress(hNtDll, "NtReadFile"));
	if (!NtOpenFile || !NtReadFile) {
		std::cerr << "Failed to get addresses of NtOpenFile and NtReadFile\n";
		FreeLibrary(hNtDll);
		return 1;
	}

	std::wstring folderPath = GetExecutableFolderPath();
	std::wstring fileNames[] = { L"\\NtReadExample.txt", L"\\NtOpenExample.txt" };

	for (const auto& fileName : fileNames) {
		std::wstring fullPath = folderPath + fileName;
		UNICODE_STRING ntPathName;
		RtlDosPathNameToNtPathName_U(fullPath.c_str(), &ntPathName, nullptr, nullptr);

		OBJECT_ATTRIBUTES objAttr;
		InitializeObjectAttributes(&objAttr, &ntPathName, OBJ_CASE_INSENSITIVE, NULL, NULL);

		IO_STATUS_BLOCK ioStatus;
		HANDLE fileHandle;

		NTSTATUS status = NtOpenFile(&fileHandle, FILE_GENERIC_READ, &objAttr, &ioStatus, FILE_SHARE_READ, FILE_NON_DIRECTORY_FILE);
		if (status != STATUS_SUCCESS) {
			std::cerr << "Failed to open file " << WStringToString(fullPath) << ". NTSTATUS Error code: 0x" << std::hex << status << "\n";
			RtlFreeUnicodeString(&ntPathName);
			continue;
		}

		HANDLE eventHandle = CreateEvent(NULL, TRUE, FALSE, NULL);
		if (eventHandle == NULL) {
			std::cerr << "Failed to create event for file " << WStringToString(fullPath) << "\n";
			CloseHandle(fileHandle);
			RtlFreeUnicodeString(&ntPathName);
			continue;
		}

		ReadFileParams* params = new ReadFileParams{ fullPath, fileHandle, eventHandle, NtReadFile };
		HANDLE thread = CreateThread(NULL, 0, ReadFileThread, params, 0, NULL);
		if (thread == NULL) {
			std::cerr << "Failed to create thread for file " << WStringToString(fullPath) << "\n";
			CloseHandle(eventHandle);
			CloseHandle(fileHandle);
			delete params;
			RtlFreeUnicodeString(&ntPathName);
			continue;
		}

		CloseHandle(thread);
		RtlFreeUnicodeString(&ntPathName); 
	}

	FreeLibrary(hNtDll);
	return 0;
}