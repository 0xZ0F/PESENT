// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format

#include <vector>
#include <iostream>
#include <array>

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include "FileHelpers.hpp"
#include "PEHelpers.hpp"
#include "Extras.hpp"
#include "DebugPrint.h"

#ifdef _WIN64
#define SRC_FILE "..\\x64\\Release\\ExampleTarget.exe"
#define DST_FILE "..\\x64\\Release\\ExampleTarget_EXTENDED.exe"
#else
#define SRC_FILE "..\\Release\\ExampleTarget.exe"
#define DST_FILE "..\\Release\\ExampleTarget_EXTENDED.exe"
#endif

#define SECTION_TO_MODIFY ".pesent"
#define SECTION_FILL "Z0F"

/// <summary>
/// Set a section's data. This will resize the section and update the headers if needed.
/// </summary>
/// <param name="peData">PE data.</param>
/// <param name="newSectionData">New section's data. Make sure this is sized exactly.</param>
/// <param name="sectionName">Name of the section to modify.</param>
/// <returns>Returns the new PE data on success, empty vector otherwise.</returns>
std::vector<BYTE> SetSectionData(std::vector<BYTE> peData, std::vector<BYTE> newSectionData, std::string sectionName)
{
	/// TODO: Update checksums.
	/// TODO: Modify or zero the rich header.

	if (newSectionData.size() > MAXDWORD)
	{
		return {};
	}

	IMAGE_DOS_HEADER* pDosHeader = NULL;
	IMAGE_NT_HEADERS* pNtHeader = NULL;
	IMAGE_OPTIONAL_HEADER* pOptHeader = NULL;
	auto SetPtrs = [&]() -> bool
		{
			return GetPtrs(peData.data(), &pDosHeader, &pNtHeader, &pOptHeader);
		};
	if(!SetPtrs() || sectionName.length() > 8)
	{
		return {};
	}

	if(sectionName.at(sectionName.length() - 1))
	{
		sectionName.append("\x00");
	}

	// Find the section to modify.
	WORD wSectionIndex = 0;
	IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);
	for(wSectionIndex = 0; wSectionIndex < pNtHeader->FileHeader.NumberOfSections; ++wSectionIndex)
	{
		if(!strncmp((char*)pSectionHeader[wSectionIndex].Name, sectionName.c_str(), sizeof(pSectionHeader[wSectionIndex].Name)))
		{
			break;
		}
	}
	pSectionHeader = &pSectionHeader[wSectionIndex];
	if(wSectionIndex >= pNtHeader->FileHeader.NumberOfSections)
	{
		return {};
	}

	DWORD dwNewSizeOriginal = (DWORD)newSectionData.size();
	{
		DWORD dwSizeNeeded = Align((DWORD)newSectionData.size(), pOptHeader->FileAlignment);
		newSectionData.resize(dwSizeNeeded);
		printf("New section data will be %zx bytes long.\n", newSectionData.size());
	}

	DWORD dwNewSizeAligned = (DWORD)newSectionData.size();
	DWORD dwOriginalSize = pSectionHeader->Misc.VirtualSize;
	DWORD dwOriginalSizeAligned = Align(dwOriginalSize, pOptHeader->SectionAlignment);
	DWORD dwAdjRaw = dwNewSizeAligned - dwOriginalSizeAligned;

	// If the new size is smaller than the original size then just overwrite the data.
	// You could still resize this section's data, but it's not necessary.
	if(dwNewSizeAligned <= pSectionHeader->SizeOfRawData)
	{
		ZeroMemory(peData.data() + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData);
		CopyMemory(peData.data() + pSectionHeader->PointerToRawData, newSectionData.data(), newSectionData.size());

		return peData;
	}

	// Remove the section data.
	auto dataStart = peData.begin() + pSectionHeader->PointerToRawData;
	peData.erase(dataStart, dataStart + pSectionHeader->SizeOfRawData);
	if(!SetPtrs())
	{
		return {};
	}
	dataStart = peData.begin() + pSectionHeader->PointerToRawData;

	// Insert the new section data.
	peData.insert(dataStart, newSectionData.begin(), newSectionData.end());
	if(!SetPtrs())
	{
		return {};
	}
	pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader) + wSectionIndex;

	// Update headers.
	pOptHeader->SizeOfImage -= dwOriginalSizeAligned;
	pOptHeader->SizeOfImage = Align(pOptHeader->SizeOfImage + dwNewSizeAligned, pOptHeader->SectionAlignment);

	// Update the section.
	DWORD dwAdjVA = Align(pSectionHeader->Misc.VirtualSize, pOptHeader->SectionAlignment);
	pSectionHeader->Misc.VirtualSize = dwNewSizeOriginal;
	dwAdjVA = Align(pSectionHeader->Misc.VirtualSize, pOptHeader->SectionAlignment) - dwAdjVA;

	pSectionHeader->SizeOfRawData = dwNewSizeAligned;
	pOptHeader->SizeOfInitializedData += dwAdjRaw;

	// If this is the last section then there's nothing else to do.
	if(wSectionIndex == pNtHeader->FileHeader.NumberOfSections - 1)
	{
		return peData;
	}

	// Update all section headers after ours.
	IMAGE_SECTION_HEADER* pNextSection = pSectionHeader + 1;
	if(!UpdateSections(pNtHeader))
	{
		return {};
	}

	// Update all data directories.
	IMAGE_DATA_DIRECTORY* pDataDir = pOptHeader->DataDirectory;
	if(!AdjustDataDirectories(pDosHeader, dwAdjVA, dwAdjRaw, pSectionHeader->VirtualAddress, pSectionHeader->PointerToRawData))
	{
		return {};
	}

	return peData;
}

/// <summary>
/// Append a section to the PE.
/// </summary>
/// <param name="peData"></param>
/// <returns>Returns true on success, false otherwise.</returns>
static inline bool DoAppend(std::vector<BYTE>& peData)
{
	char sectionFill = 'A';
	size_t numToAdd = 10;
	printf("Adding %zu sections.\n", numToAdd);
	for(size_t x = 0; x < numToAdd; ++x, ++sectionFill)
	{
		std::vector<BYTE> newSectionData(0x200);
		memset(newSectionData.data(), sectionFill, newSectionData.size());
		std::string sectionName = ".hlpme";

		peData = AppendSection(peData, newSectionData, sectionName);
		if(peData.empty())
		{
			fprintf(stderr, "Append failed.\n");
			return false;
		}
	}

	return true;
}

/// <summary>
/// Extend a section's (SECTION_TO_MODIFY) data even if it's not the last section.
/// This won't work for most situations.
/// </summary>
/// <param name="peData"></param>
/// <returns>Returns true on success, false otherwise.</returns>
static inline bool DoExtend(std::vector<BYTE>& peData)
{
	std::vector<BYTE> newData(0x13433);
	for(size_t x = 0; x < newData.size() - sizeof(SECTION_FILL); x += 4)
	{
		CopyMemory(&newData[x], SECTION_FILL, sizeof(SECTION_FILL));
	}

	peData = SetSectionData(peData, newData, SECTION_TO_MODIFY);
	if(peData.empty())
	{
		fprintf(stderr, "Failed to set section data.\n");
		return false;
	}

	return true;
}

static inline bool RunResult(const char* pszFile)
{
	STARTUPINFOA si = { sizeof(si) };
	PROCESS_INFORMATION pi = { 0 };

	if(!CreateProcessA(pszFile, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
	{
		if(ERROR_BAD_EXE_FORMAT == GetLastError())
		{
			fprintf(stderr, "Invalid executable format.\n");
		}
		else
		{
			fprintf(stderr, "Failed to create process. Error: %lu\n", GetLastError());
		}

		return false;
	}

	if(WAIT_OBJECT_0 != WaitForSingleObject(pi.hProcess, INFINITE))
	{
		DebugPrint("Failed to wait for process. Error: %lu\n", GetLastError());
	}
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	return true;
}

int main()
{
	std::vector<BYTE> fileData = ReadFile(SRC_FILE);
	if(fileData.empty())
	{
		fprintf(stderr, "Failed to read file.\n");
		return -1;
	}

	if(!DoExtend(fileData))
	{
		return -1;
	}

	if(!WriteToFile(DST_FILE, fileData))
	{
		fprintf(stderr, "Failed to write to file.\n");
		return -1;
	}

	if(!RunResult(DST_FILE))
	{
		return -1;
	}

	return 0;
}