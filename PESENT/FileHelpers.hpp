#pragma once

#include <vector>
#include <string>
#include <iostream>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>

std::vector<BYTE> ReadFile(const std::string& path)
{
	HANDLE hFile = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if(hFile == INVALID_HANDLE_VALUE)
	{
		std::cerr << "Failed to open file." << std::endl;
		return {};
	}

	DWORD dwFileSize = GetFileSize(hFile, NULL);
	if(dwFileSize == INVALID_FILE_SIZE)
	{
		std::cerr << "Failed to get file size." << std::endl;
		CloseHandle(hFile);
		return {};
	}

	std::vector<BYTE> buffer(dwFileSize);
	DWORD dwBytesRead = 0;
	if(!ReadFile(hFile, buffer.data(), dwFileSize, &dwBytesRead, NULL))
	{
		std::cerr << "Failed to read file." << std::endl;
		CloseHandle(hFile);
		return {};
	}

	CloseHandle(hFile);

	return buffer;
}

bool WriteToFile(const std::string& path, const std::vector<BYTE>& vData)
{
	HANDLE hFile = CreateFileA(path.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if(hFile == INVALID_HANDLE_VALUE)
	{
		std::cerr << "Failed to open file." << std::endl;
		return false;
	}

	DWORD dwWritten = 0;
	if(!WriteFile(hFile, vData.data(), (DWORD)vData.size(), &dwWritten, NULL))
	{
		CloseHandle(hFile);
		return false;
	}

	CloseHandle(hFile);

	return true;
}
