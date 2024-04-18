#pragma once

#include <vector>
#include <iostream>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>

#include "PEHelpers.hpp"

bool PrintSections(const std::vector<BYTE>& fileData)
{
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNtHeader = NULL;
	if(!GetPtrs(fileData.data(), &pDosHeader, &pNtHeader, NULL))
	{
		return false;
	}

	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);
	for(int i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++)
	{
		std::cout << "Section: " << pSectionHeader[i].Name << std::endl;
		std::cout << "Virtual Address: " << pSectionHeader[i].VirtualAddress << std::endl;
		std::cout << "Virtual Size: " << pSectionHeader[i].Misc.VirtualSize << std::endl;
		std::cout << "Raw Size: " << pSectionHeader[i].SizeOfRawData << std::endl;
		std::cout << "Raw Offset: " << pSectionHeader[i].PointerToRawData << std::endl;
		std::cout << std::endl;
	}

	return true;
}

bool PrintImports(PIMAGE_NT_HEADERS pNtHeader, const std::vector<BYTE>& fileBytes)
{
	IMAGE_OPTIONAL_HEADER* pOptionalHeader = &pNtHeader->OptionalHeader;
	IMAGE_DATA_DIRECTORY* pImportDirectory = &pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	IMAGE_IMPORT_DESCRIPTOR* pImportDescriptor = (IMAGE_IMPORT_DESCRIPTOR*)(fileBytes.data() + RVAToFileOffset(pNtHeader, pImportDirectory->VirtualAddress));
	while(pImportDescriptor->Name)
	{
		std::cout << "DLL: " << (char*)(fileBytes.data() + RVAToFileOffset(pNtHeader, pImportDescriptor->Name)) << std::endl;

		IMAGE_THUNK_DATA* thunkData = (IMAGE_THUNK_DATA*)(fileBytes.data() + RVAToFileOffset(pNtHeader, pImportDescriptor->OriginalFirstThunk));
		while(thunkData->u1.AddressOfData)
		{
			if(thunkData->u1.Ordinal & IMAGE_ORDINAL_FLAG)
			{
				std::cout << "\tOrdinal:  " << IMAGE_ORDINAL(thunkData->u1.Ordinal) << std::endl;
			}
			else
			{
				IMAGE_IMPORT_BY_NAME* importByName = (IMAGE_IMPORT_BY_NAME*)(fileBytes.data() + RVAToFileOffset(pNtHeader, (DWORD)thunkData->u1.AddressOfData));
				std::cout << "\tFunction: " << importByName->Name << std::endl;
			}

			thunkData++;
		}

		std::cout << std::endl;

		pImportDescriptor++;
	}

	return true;
}

std::vector<BYTE> AddSectionHeaderSpace(std::vector<BYTE> data, DWORD dwToAdd)
{
	/*
		* Insert the requested amount of data after the headers.
		  * End of headers can be found with pOptHeader->SizeOfHeaders
			which can be used as a file offset.
		  * Respect alignment.
		* Update pOptHeader->SizeOfHeaders.
		* Update each section's PointerToRawData (+= amount added w/ alignment).
	*/

	IMAGE_DOS_HEADER* pDosHeader = NULL;
	IMAGE_NT_HEADERS* pNtHeader = NULL;
	IMAGE_OPTIONAL_HEADER* pOptHeader = NULL;
	IMAGE_FILE_HEADER* pFileHeader = NULL;

	auto SetPtrs = [&]() -> bool
		{
			if(!GetPtrs(data.data(), &pDosHeader, &pNtHeader, &pOptHeader))
			{
				return false;
			}
			pFileHeader = &pNtHeader->FileHeader;

			return true;
		};

	if(!SetPtrs() || !dwToAdd)
	{
		return {};
	}

	// Update to make dwToAdd + pOptHeader->SizeOfHeaders always hit alignment to avoid extra calls to Align().
	dwToAdd = Align(pOptHeader->SizeOfHeaders + dwToAdd, pOptHeader->FileAlignment) - pOptHeader->SizeOfHeaders;

	// Insert data after the headers which is at file offset pOptHeader->SizeOfHeaders.
	data.insert(data.begin() + pOptHeader->SizeOfHeaders, dwToAdd, 0);
	if(!SetPtrs())
	{
		return {};
	}

	// Already aligned (see above).
	pOptHeader->SizeOfHeaders += dwToAdd;

	// Update the PointerToRawData for each section
	IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);
	for(WORD i = 0; i < pNtHeader->FileHeader.NumberOfSections; ++i)
	{
		pSectionHeader[i].PointerToRawData += dwToAdd;
	}

	return data;
}

std::vector<BYTE> AppendSection(const std::vector<BYTE>& originalData, const std::vector<BYTE>& sectionData, const std::string& name)
{
	/*
		The section header and data are seperate, pay attention to variable names.

		Section headers have a predefined region they can be put into. If there's
		space for a header after the last header, you can overwrite that region with
		the new header. If there is not enough space, you must cave out space. Creating
		extra space for the header, if needed, is done with AddSectionHeaderSpace().

		1. Add a section header.
			* Check if there is space for a new header, if not, make space.

			The following fields in the header need to be set.
			* Name - Easiest thing to do is have this be a NULL terminated string no larger than 8 characters.
				* It's possible for this name to be longer. But it's complicated and unnecessary.
			* Misc.VirtualSize - This is not aligned, and is the raw size of the data of this section.
			* VirtualAddress - This is going to be the last section's VA plus it's Misc.VirtualSize aligned to SectionAlignment.
			* SizeOfRawData - Size of the section's data aligned to FileAlignment.
			* PointerToRawData - This is the file offset to the section's data.
				* Usually you'll set this to the previous section's PointerToRawData plus it's SizeOfRawData.
			* Characteristics - Section characteristics such as IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE.
			* ... - Rest of the fields are not used in this case.

		2. Add section data.
			Data can go anywhere, really, as long as PointerToRawData (file offset) points to it.
			Generally data and headers are in the same order, so when appending
			a section you append the section data to the end of the file.
			* Append section data to the end of the last section, (not always EOF).
			* Set the header's pointers and addresses.

		3. Update other headers.
			* FileHeader->NumberOfSections needs to be incremented.
			* OptionalHeader->SizeOfImage needs to be updated to reflect the added data.
			  If additional space is needed for the header, AddSectionHeaderSpace() handles that too.
	*/

	if(name.length() > 8)
	{
		return {};
	}

	std::vector<BYTE> result = originalData;
	IMAGE_DOS_HEADER* pDosHeader = NULL;
	IMAGE_NT_HEADERS* pNtHeader = NULL;
	IMAGE_OPTIONAL_HEADER* pOptHeader = NULL;
	IMAGE_SECTION_HEADER* pLastSection = NULL;
	DWORD dwHeaderOffset = 0;

	auto Init = [&]() -> bool
		{
			if(!GetPtrs(result.data(), &pDosHeader, &pNtHeader, &pOptHeader))
			{
				return false;
			}

			pLastSection = IMAGE_FIRST_SECTION(pNtHeader) + (pNtHeader->FileHeader.NumberOfSections - 1);
			dwHeaderOffset = (DWORD)((BYTE*)pLastSection - result.data() + IMAGE_SIZEOF_SECTION_HEADER);

			return true;
		};
	Init();

	// Make sure there is space for the new section. If not, add space.
	if(dwHeaderOffset + IMAGE_SIZEOF_SECTION_HEADER > pOptHeader->SizeOfHeaders)
	{
		result = AddSectionHeaderSpace(result, IMAGE_SIZEOF_SECTION_HEADER);
		if(result.empty())
		{
			return {};
		}

		// Re-init now that vector has changed.
		if(!Init())
		{
			return {};
		}
	}

	// Vector will be used at the end for insertion.
	std::vector<BYTE> newHeaderData(sizeof(IMAGE_SECTION_HEADER));
	auto pNewHeader = (IMAGE_SECTION_HEADER*)newHeaderData.data();

	ZeroMemory(pNewHeader->Name, sizeof(pNewHeader->Name));
	if(strncpy_s((char*)pNewHeader->Name, sizeof(pNewHeader->Name), name.c_str(), name.length()))
	{
		return {};
	}

	pNewHeader->Misc.VirtualSize = (DWORD)sectionData.size();

	pNewHeader->VirtualAddress = Align(pLastSection->VirtualAddress + pLastSection->Misc.VirtualSize, pOptHeader->SectionAlignment);

	pNewHeader->SizeOfRawData = Align((DWORD)sectionData.size(), pOptHeader->FileAlignment);
	pNewHeader->PointerToRawData = Align(pLastSection->PointerToRawData + pLastSection->SizeOfRawData, pOptHeader->FileAlignment);

	pNewHeader->Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

	// Set the section header
	CopyMemory(result.data() + dwHeaderOffset, newHeaderData.data(), newHeaderData.size());

	// Insert section data
	result.insert(result.begin() + pNewHeader->PointerToRawData, sectionData.begin(), sectionData.end());

	// Need to re-fetch ptrs now that result has been moved (vector insert caused resize).
	if(!Init())
	{
		return {};
	}

	pNtHeader->FileHeader.NumberOfSections++;
	pOptHeader->SizeOfImage = Align(pNewHeader->VirtualAddress + pNewHeader->Misc.VirtualSize, pOptHeader->SectionAlignment);

	return result;
}