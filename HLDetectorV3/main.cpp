//#pragma once
//#include <Windows.h>
//#include "hwbp_hook.hpp"
//#include <cstdio>
//#include <winternl.h>
//#include <iostream>
//#include <fstream>
//#include "LazyImport.hpp"
//#include "XorString.hpp"
//
//#ifdef _DEBUG
//std::string wstringToString(const std::wstring& wstr) {
//	if (wstr.empty()) {
//		return std::string();
//	}
//
//	int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);
//	std::string strTo(sizeNeeded, 0);
//	WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &strTo[0], sizeNeeded, nullptr, nullptr);
//	strTo.pop_back();
//	return strTo;
//}
//void writeToLog(const std::string& text) {
//	std::ofstream logFile("logs.txt", std::ios::app);
//	if (logFile.is_open()) {
//		logFile << text << std::endl;
//		logFile.close();
//	}
//	else {
//		std::cerr << "Unable to open logs.txt for writing." << std::endl;
//	}
//}
//void writeToLog(const std::wstring& wtext) {
//	writeToLog(wstringToString(wtext));
//}
//void writeToLogW(const std::string& text) {
//	std::ofstream logFile("logWW.txt", std::ios::app);
//	if (logFile.is_open()) {
//		logFile << text << std::endl;
//		logFile.close();
//	}
//	else {
//		std::cerr << "Unable to open logs.txt for writing." << std::endl;
//	}
//}
//
//void writeToLogW(const std::wstring& wtext) {
//	writeToLog(wstringToString(wtext));
//}
//#endif
//NTSTATUS NTAPI HookedNtOpenFile(
//	PHANDLE FileHandle,
//	ACCESS_MASK DesiredAccess,
//	POBJECT_ATTRIBUTES ObjectAttributes,
//	PIO_STATUS_BLOCK IoStatusBlock,
//	ULONG ShareAccess,
//	ULONG OpenOptions
//) {
//	if (ObjectAttributes != nullptr)
//	{
//		if (ObjectAttributes->ObjectName != nullptr && ObjectAttributes->ObjectName->Buffer != nullptr)
//		{
//			std::wstring a = XorStringW(L"\\data\\images\\");
//			std::wstring b = XorStringW(L"\\data\\config\\");
//			std::wstring c = XorStringW(L"HLBot");
//
//			if ((std::wcsstr(ObjectAttributes->ObjectName->Buffer, a.c_str())) || (std::wcsstr(ObjectAttributes->ObjectName->Buffer, b.c_str()) || (std::wcsstr(ObjectAttributes->ObjectName->Buffer, c.c_str()))))
//			{
//#ifdef _DEBUG
//				writeToLog(ObjectAttributes->ObjectName->Buffer);
//#endif
//				LI_FN(ExitProcess)(0);
//				LI_FN(__fastfail)(0);
//			}
//		}
//
//	}
//	return hook_manager::get()[XorString("NtOpenFile")]->call<NTSTATUS>(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions);
//}
//
//
//std::wstring GetFilePathFromHandle(HANDLE hFile) {
//	TCHAR filePath[MAX_PATH] = { 0 };
//	if (hFile == INVALID_HANDLE_VALUE)
//		return L"";
//
//	DWORD dwRet = GetFinalPathNameByHandleW(hFile, (LPWSTR)filePath, MAX_PATH, FILE_NAME_NORMALIZED);
//	if (dwRet == 0) {
//		return L"";
//	}
//
//	std::wstring path((LPWSTR)filePath);
//
//	if (path.find(XorStringW(L"\\\\?\\")) == 0) {
//		path = path.substr(4);
//	}
//
//	return path;
//}
//NTSTATUS NTAPI HookNtReadFile(
//	HANDLE           FileHandle,
//	HANDLE           Event,
//	PIO_APC_ROUTINE  ApcRoutine,
//	PVOID            ApcContext,
//	PIO_STATUS_BLOCK IoStatusBlock,
//	PVOID            Buffer,
//	ULONG            Length,
//	PLARGE_INTEGER   ByteOffset,
//	PULONG           Key
//) {
//
//	std::wstring filePath = GetFilePathFromHandle(FileHandle);
//	std::wstring a = XorStringW(L"\\data\\images\\");
//	std::wstring b = XorStringW(L"\\data\\config\\");
//	std::wstring c = XorStringW(L"HLBot");
//	if ((std::wcsstr(filePath.c_str(), a.c_str())) || (std::wcsstr(filePath.c_str(), b.c_str()) || (std::wcsstr(filePath.c_str(), c.c_str()))))
//	{
//#ifdef DEBUG
//		writeToLogW(filePath.c_str());
//#endif // DEBUG
//
//		LI_FN(ExitProcess)(0);
//		LI_FN(__fastfail)(0);
//
//	}
//	return hook_manager::get()[XorString("NtReadFile")]->call<NTSTATUS>(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
//}
//
//void InitHLDetv3() {
//	auto NtOpenFileOff = LI_FN(GetProcAddress)(LI_FN(GetModuleHandleA)(XorString("ntdll.dll")), XorString("NtOpenFile"));
//	auto NtReadFileOff = LI_FN(GetProcAddress)(LI_FN(GetModuleHandleA)(XorString("ntdll.dll")), XorString("NtReadFile"));
//	auto& mgr = hook_manager::get();
//	mgr.init();
//	mgr[XorString("NtOpenFile")]->hook(NtOpenFileOff, HookedNtOpenFile);
//	mgr[XorString("NtReadFile")]->hook(NtReadFileOff, HookNtReadFile);
//}