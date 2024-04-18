// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format

#include <vector>
#include <iostream>
#include <array>

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include "FileHelpers.hpp"
#include "PEHelpers.hpp"

#ifdef _WIN64
#define SRC_FILE "..\\x64\\Debug\\ExampleTarget.exe"
#define DST_FILE "..\\x64\\Debug\\ExampleTarget_EXTENDED.exe"
#else
#define SRC_FILE "..\\Debug\\ExampleTarget.exe"
#define DST_FILE "..\\Debug\\ExampleTarget_EXTENDED.exe"
#endif

#define SECTION_TO_MODIFY ".stuff"
#define RUN_NEW_FILE 1

/// <summary>
/// Updates the VirtualAddress and PointerToRawData for all sections.
/// Note: This assumes section headers and data are in the same order.
/// </summary>
/// <param name="pNtHeader">Pointer to the NT header.</param>
/// <returns>Returns true on success, false otherwise.</returns>
bool UpdateSections(IMAGE_NT_HEADERS* pNtHeader)
{
	/*
		The section's PointerToRawData is obtained by adding the previous
		sections PointerToRawData and it's SizeOfRawData.

		Sections can have a SizeOfRawData of zero if the section contains
		uninitialized data. The PointerToRawData will also be zero.
		Because of this, it's important to have a way to get the next available
		raw address rather than relying on the previous section's raw address.

		The VirtualAddress for each section is updated by adding the previous
		section's VirtualAddress and it's Misc.VirtualSize.
	*/

	IMAGE_OPTIONAL_HEADER* pOptHeader = &pNtHeader->OptionalHeader;
	IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);

	// Set the first section's information.
	pSectionHeader->VirtualAddress = Align(pOptHeader->SizeOfHeaders, pOptHeader->SectionAlignment);
	if(pSectionHeader->SizeOfRawData)
	{
		// First section's pointer is set to after the headers.
		pSectionHeader->PointerToRawData = Align(pOptHeader->SizeOfHeaders, pOptHeader->FileAlignment);
	}
	else
	{
		// If SizeOfRawData is zero (section contains uninitialized code) then the pointer is also zero.
		pSectionHeader->PointerToRawData = 0;
	}

	// Update VA and PTRD for all sections.
	for(WORD x = 1; x < pNtHeader->FileHeader.NumberOfSections; ++x)
	{
		IMAGE_SECTION_HEADER* pPrevSection = &IMAGE_FIRST_SECTION(pNtHeader)[x - 1];
		pSectionHeader[x].VirtualAddress = Align(pPrevSection->VirtualAddress + pPrevSection->Misc.VirtualSize, pOptHeader->SectionAlignment);

		// This helps handling with sections that have a raw size of 0.
		// Specifically, with keeping track of the hext available spot.
		DWORD dwNextPtrToRaw = Align(pPrevSection->PointerToRawData + pPrevSection->SizeOfRawData, pOptHeader->FileAlignment);
		if(!dwNextPtrToRaw)
		{
			dwNextPtrToRaw = pOptHeader->SizeOfHeaders;
		}

		if(pSectionHeader[x].SizeOfRawData)
		{
			pSectionHeader[x].PointerToRawData = dwNextPtrToRaw;
		}
		else
		{
			pSectionHeader[x].PointerToRawData = 0;
		}
	}

	return true;
}

// Implement CalculateChecksum
DWORD CalculateChecksum(const BYTE* pData, DWORD dwSize)
{
	DWORD dwChecksum = 0;
	DWORD dwChecksumOffset = 0;
	DWORD dwChecksumSize = 0;

	// Get the checksum offset and size.
	IMAGE_NT_HEADERS* pNtHeader = NULL;
	IMAGE_OPTIONAL_HEADER* pOptHeader = NULL;
	if(!GetPtrs(pData, NULL, &pNtHeader, &pOptHeader))
	{
		return 0;
	}

	// Checksum is calculated from the beginning of the file to the Checksum field.
	dwChecksumOffset = (DWORD)((BYTE*)&pOptHeader->CheckSum - pData);
	dwChecksumSize = dwChecksumOffset + sizeof(pOptHeader->CheckSum);

	// Calculate the checksum.
	for(DWORD x = 0; x < dwSize; x += sizeof(DWORD))
	{
		DWORD dwData = 0;
		memcpy(&dwData, pData + x, sizeof(DWORD));
		dwChecksum += dwData;
	}

	// Add the size of the file to the checksum.
	dwChecksum += dwSize;

	return dwChecksum;
}


std::vector<BYTE> SetSectionData(std::vector<BYTE> peData, const std::vector<BYTE>& newSectionData, std::string sectionName)
{
	IMAGE_NT_HEADERS* pNtHeader = NULL;
	IMAGE_OPTIONAL_HEADER* pOptHeader = NULL;
	auto SetPtrs = [&]() -> bool
		{
			return GetPtrs(peData.data(), NULL, &pNtHeader, &pOptHeader);
		};
	if(!SetPtrs() || sectionName.length() > 8)
	{
		return {};
	}

	if(sectionName.at(sectionName.length() - 1))
	{
		sectionName.append("\x00");
	}

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

	DWORD dwNewSizeAligned = Align((DWORD)newSectionData.size(), pOptHeader->FileAlignment);
	DWORD dwOriginalSize = pSectionHeader->Misc.VirtualSize;
	DWORD dwOriginalSizeAligned = Align(dwOriginalSize, pOptHeader->SectionAlignment);

	/// TODO: Make this work for dwNewSizeAligned < dwOriginalSizeAligned
	DWORD dwSizeDiff = dwNewSizeAligned - dwOriginalSizeAligned;

	pOptHeader->SizeOfImage -= dwOriginalSizeAligned;
	pOptHeader->SizeOfImage = Align(pOptHeader->SizeOfImage + dwNewSizeAligned, pOptHeader->SectionAlignment);

	pSectionHeader->Misc.VirtualSize = (DWORD)newSectionData.size();
	pSectionHeader->SizeOfRawData = dwNewSizeAligned;

	// Update all sections after ours
	if(!UpdateSections(pNtHeader))
	{
		return {};
	}

	/// TODO: Update the checksum.

	/// TODO: Modify or zero the rich header.

	// Update the addresses for the data directories
	IMAGE_DATA_DIRECTORY* pDataDir = pOptHeader->DataDirectory;
	for(int x = 0; x < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; ++x)
	{
		if(pDataDir[x].VirtualAddress > pSectionHeader->VirtualAddress)
		{
			pDataDir[x].VirtualAddress += dwSizeDiff;
		}
	}


	// Update the resources
	IMAGE_RESOURCE_DIRECTORY* pResDir = (IMAGE_RESOURCE_DIRECTORY*)(peData.data() + RVAToFileOffset(pNtHeader, pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress));
	IMAGE_RESOURCE_DIRECTORY_ENTRY* pResDirEntry = (IMAGE_RESOURCE_DIRECTORY_ENTRY*)(pResDir + 1);
	for(int x = 0; x < pResDir->NumberOfIdEntries + pResDir->NumberOfNamedEntries; ++x)
	{
		if(pResDirEntry[x].OffsetToData > pSectionHeader->VirtualAddress)
		{
			pResDirEntry[x].OffsetToData += dwSizeDiff;
		}
	}

	// Update base reloc
	IMAGE_BASE_RELOCATION* pBaseReloc = (IMAGE_BASE_RELOCATION*)(peData.data() + RVAToFileOffset(pNtHeader, pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress));
	while(pBaseReloc->VirtualAddress)
	{
		WORD* pReloc = (WORD*)(pBaseReloc + 1);
		for(int x = 0; x < (pBaseReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD); ++x)
		{
			if((*pReloc & 0xFFF) > pSectionHeader->VirtualAddress)
			{
				*pReloc += (WORD)dwSizeDiff;
			}
			++pReloc;
		}

		pBaseReloc = (IMAGE_BASE_RELOCATION*)((BYTE*)pBaseReloc + pBaseReloc->SizeOfBlock);
	}

	return peData;
}

int main()
{
	// Read file
	std::vector<BYTE> fileData = ReadFile(SRC_FILE);
	if(fileData.empty())
	{
		fprintf(stderr, "Failed to read file.\n");
		return -1;
	}

#ifdef APPEND_SECTION
	char sectionFill = 'A';
	for(size_t x = 0; x < 10; ++x, ++sectionFill)
	{
		std::vector<BYTE> newSectionData(0x200);
		memset(newSectionData.data(), sectionFill, newSectionData.size());
		std::string sectionName = ".hlpme";

		newHeader = AppendSection(newHeader, newSectionData, sectionName);
		if(newHeader.empty())
		{
			fprintf(stderr, "Append failed.\n");
			return -1;
		}
	}
#endif

	std::vector<BYTE> newData(0x10000);
	memset(newData.data(), 'Z', newData.size());
	newData[4] = 0;

	fileData = SetSectionData(fileData, newData, SECTION_TO_MODIFY);
	if(fileData.empty())
	{
		fprintf(stderr, "Failed to set section data.\n");
		return -1;
	}

	if(!WriteToFile(DST_FILE, fileData))
	{
		fprintf(stderr, "Failed to write to file.\n");
		return -1;
	}

#ifdef RUN_NEW_FILE
	STARTUPINFOA si = { sizeof(si) };
	PROCESS_INFORMATION pi = { 0 };

	if(!CreateProcessA(DST_FILE, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
	{
		if(ERROR_BAD_EXE_FORMAT == GetLastError())
		{
			fprintf(stderr, "Invalid executable format.\n");
		}
		else
		{
			fprintf(stderr, "Failed to create process. Error: %lu\n", GetLastError());
		}
		return -1;
	}

	WaitForSingleObject(pi.hProcess, INFINITE);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
#endif

	return 0;
}