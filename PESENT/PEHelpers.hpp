#pragma once

#include <iostream>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>

template <typename T>
static inline T Align(T val, T alignment)
{
	T result;
	T remainder;

	remainder = val % alignment;
	result = remainder ? val + (alignment - remainder) : val;

	return result;
}

bool GetPtrs(const BYTE* pData, IMAGE_DOS_HEADER** ppDosHeader = NULL, IMAGE_NT_HEADERS** ppNtHeader = NULL, IMAGE_OPTIONAL_HEADER** ppOptHeader = NULL)
{
	IMAGE_DOS_HEADER* pDos = (PIMAGE_DOS_HEADER)pData;
	if(pDos->e_magic != IMAGE_DOS_SIGNATURE)
	{
		std::cerr << "Invalid DOS signature." << std::endl;
		return false;
	}

	auto pNt = (IMAGE_NT_HEADERS*)(pData + pDos->e_lfanew);
	if(pNt->Signature != IMAGE_NT_SIGNATURE)
	{
		std::cerr << "Invalid NT signature." << std::endl;
		return false;
	}

	IMAGE_OPTIONAL_HEADER* pOpt = &pNt->OptionalHeader;

	if(ppDosHeader)
	{
		*ppDosHeader = pDos;
	}

	if(ppNtHeader)
	{
		*ppNtHeader = pNt;
	}

	if(ppOptHeader)
	{
		*ppOptHeader = pOpt;
	}

	return true;
}

// https://stackoverflow.com/questions/45212489/image-section-headers-virtualaddress-and-pointertorawdata-difference
// https://pastebin.com/pttDSTRz
DWORD RVAToFileOffset(PIMAGE_NT_HEADERS pNTHeader, DWORD RVA)
{
	PIMAGE_FILE_HEADER fileHeader = &(pNTHeader->FileHeader);
	PIMAGE_OPTIONAL_HEADER optionalHeader = &(pNTHeader->OptionalHeader);

	WORD sizeOfOptionalHeader = fileHeader->SizeOfOptionalHeader;
	WORD numberOfSections = fileHeader->NumberOfSections;

	PIMAGE_SECTION_HEADER firstSectionHeader;
	firstSectionHeader = (PIMAGE_SECTION_HEADER)(((PBYTE)optionalHeader) + sizeOfOptionalHeader);

	PIMAGE_SECTION_HEADER section = firstSectionHeader;
	for(int i = 0; i < numberOfSections; i++)
	{

		DWORD VirtualAddress = section->VirtualAddress;
		DWORD VirtualSize = section->Misc.VirtualSize;

		if(VirtualAddress <= RVA && RVA < VirtualAddress + VirtualSize)
		{
			// RVA is in this section.
			return (RVA - VirtualAddress) + section->PointerToRawData;
		}

		section = (PIMAGE_SECTION_HEADER)(((PBYTE)section) + IMAGE_SIZEOF_SECTION_HEADER);
	}

	return 0;
}
