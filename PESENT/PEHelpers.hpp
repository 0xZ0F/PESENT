#pragma once

#include <string>
#include <iostream>
#include <functional>

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
	if (pDos->e_magic != IMAGE_DOS_SIGNATURE)
	{
		std::cerr << "Invalid DOS signature." << std::endl;
		return false;
	}

	auto pNt = (IMAGE_NT_HEADERS*)(pData + pDos->e_lfanew);
	if (pNt->Signature != IMAGE_NT_SIGNATURE)
	{
		std::cerr << "Invalid NT signature." << std::endl;
		return false;
	}

	IMAGE_OPTIONAL_HEADER* pOpt = &pNt->OptionalHeader;

	if (ppDosHeader)
	{
		*ppDosHeader = pDos;
	}

	if (ppNtHeader)
	{
		*ppNtHeader = pNt;
	}

	if (ppOptHeader)
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
	for (int i = 0; i < numberOfSections; i++)
	{

		DWORD VirtualAddress = section->VirtualAddress;
		DWORD VirtualSize = section->Misc.VirtualSize;

		if (VirtualAddress <= RVA && RVA < VirtualAddress + VirtualSize)
		{
			// RVA is in this section.
			return (RVA - VirtualAddress) + section->PointerToRawData;
		}

		section = (PIMAGE_SECTION_HEADER)(((PBYTE)section) + IMAGE_SIZEOF_SECTION_HEADER);
	}

	return 0;
}

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
	if (pSectionHeader->SizeOfRawData)
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
	for (WORD x = 1; x < pNtHeader->FileHeader.NumberOfSections; ++x)
	{
		IMAGE_SECTION_HEADER* pPrevSection = &IMAGE_FIRST_SECTION(pNtHeader)[x - 1];
		pSectionHeader[x].VirtualAddress = Align(pPrevSection->VirtualAddress + pPrevSection->Misc.VirtualSize, pOptHeader->SectionAlignment);

		// This helps handling with sections that have a raw size of 0.
		// Specifically, with keeping track of the hext available spot.
		DWORD dwNextPtrToRaw = Align(pPrevSection->PointerToRawData + pPrevSection->SizeOfRawData, pOptHeader->FileAlignment);
		if (!dwNextPtrToRaw)
		{
			dwNextPtrToRaw = pOptHeader->SizeOfHeaders;
		}

		if (pSectionHeader[x].SizeOfRawData)
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

/// <summary>
/// https://stackoverflow.com/questions/49066842/resourceentries-rvas-of-a-resource-table-need-relocation-upon-copying-it-to-a-di
/// </summary>
/// <param name="pFirstResource"></param>
/// <param name="pCurrentResource"></param>
/// <param name="dwDelta"></param>
static void DoAdjustResources(PBYTE pFirstResource, PIMAGE_RESOURCE_DIRECTORY pCurrentResource, DWORD dwDelta)
{
	if (DWORD NumberOfEntries = pCurrentResource->NumberOfNamedEntries + pCurrentResource->NumberOfIdEntries)
	{
		PIMAGE_RESOURCE_DIRECTORY_ENTRY pirde = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pCurrentResource + 1);

		do
		{
			if (pirde->DataIsDirectory)
			{
				DoAdjustResources(pFirstResource,
					(PIMAGE_RESOURCE_DIRECTORY)(pFirstResource + pirde->OffsetToDirectory),
					dwDelta);
			}
			else
			{
				PIMAGE_RESOURCE_DATA_ENTRY data =
					(PIMAGE_RESOURCE_DATA_ENTRY)(pFirstResource + pirde->OffsetToData);

				data->OffsetToData += dwDelta;
			}

		} while (pirde++, --NumberOfEntries);
	}
}

static inline bool AdjustExports(IMAGE_DOS_HEADER* pDosHeader, DWORD dwAdjVA, DWORD dwAdjRaw, DWORD adjAboveVA, DWORD adjAboveRawPtr)
{
	IMAGE_NT_HEADERS* pNtHeader = NULL;
	IMAGE_OPTIONAL_HEADER* pOptHeader = NULL;
	if (!GetPtrs((BYTE*)pDosHeader, NULL, &pNtHeader, &pOptHeader))
	{
		return false;
	}

	IMAGE_DATA_DIRECTORY* pDataDir = &pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	if (!pDataDir->VirtualAddress)
	{
		return true;
	}

	BYTE* pStart = (BYTE*)pDosHeader;
	auto pExportDir = (IMAGE_EXPORT_DIRECTORY*)(pStart + RVAToFileOffset(pNtHeader, pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress));
	if (pExportDir->AddressOfFunctions > adjAboveVA)
	{
		pExportDir->AddressOfFunctions += dwAdjVA;
	}
	if (pExportDir->AddressOfNames > adjAboveVA)
	{
		pExportDir->AddressOfNames += dwAdjVA;
	}
	if (pExportDir->AddressOfNameOrdinals > adjAboveVA)
	{
		pExportDir->AddressOfNameOrdinals += dwAdjVA;
	}

	return true;
}

static inline bool AdjustImports(IMAGE_DOS_HEADER* pDosHeader, DWORD dwAdjVA, DWORD dwAdjRaw, DWORD adjAboveVA, DWORD adjAboveRawPtr)
{
	IMAGE_NT_HEADERS* pNtHeader = NULL;
	IMAGE_OPTIONAL_HEADER* pOptHeader = NULL;
	if (!GetPtrs((BYTE*)pDosHeader, NULL, &pNtHeader, &pOptHeader))
	{
		return false;
	}

	IMAGE_DATA_DIRECTORY* pDataDir = &pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if (!pDataDir->VirtualAddress)
	{
		return true;
	}

	BYTE* pStart = (BYTE*)pDosHeader;
	auto pImportDir = (IMAGE_IMPORT_DESCRIPTOR*)(pStart + RVAToFileOffset(pNtHeader, pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress));
	while (pImportDir->Name)
	{
		if (pImportDir->OriginalFirstThunk > adjAboveVA)
		{
			pImportDir->OriginalFirstThunk += dwAdjVA;
		}
		if (pImportDir->FirstThunk > adjAboveVA)
		{
			pImportDir->FirstThunk += dwAdjVA;
		}

		++pImportDir;
	}

	return true;
}

static inline bool AdjustResources(IMAGE_DOS_HEADER* pDosHeader, DWORD dwAdjVA, DWORD dwAdjRaw, DWORD adjAboveVA, DWORD adjAboveRawPtr)
{
	IMAGE_NT_HEADERS* pNtHeader = NULL;
	IMAGE_OPTIONAL_HEADER* pOptHeader = NULL;
	if (!GetPtrs((BYTE*)pDosHeader, NULL, &pNtHeader, &pOptHeader))
	{
		return false;
	}

	IMAGE_DATA_DIRECTORY* pDataDir = &pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
	if (!pDataDir->VirtualAddress)
	{
		return true;
	}

	IMAGE_DATA_DIRECTORY resourceDirectory = pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
	if (resourceDirectory.Size == 0)
	{
		return true;
	}

	DWORD dwResourceBase = RVAToFileOffset(pNtHeader, resourceDirectory.VirtualAddress);
	IMAGE_RESOURCE_DIRECTORY* pResourceDir = (IMAGE_RESOURCE_DIRECTORY*)((BYTE*)pDosHeader + dwResourceBase);

	DoAdjustResources((BYTE*)pResourceDir, pResourceDir, dwAdjVA);

	return true;
}

static inline bool AdjustExceptions(IMAGE_DOS_HEADER* pDosHeader, DWORD dwAdjVA, DWORD dwAdjRaw, DWORD adjAboveVA, DWORD adjAboveRawPtr)
{
	IMAGE_NT_HEADERS* pNtHeader = NULL;
	IMAGE_OPTIONAL_HEADER* pOptHeader = NULL;
	if (!GetPtrs((BYTE*)pDosHeader, NULL, &pNtHeader, &pOptHeader))
	{
		return false;
	}

	IMAGE_DATA_DIRECTORY* pDataDir = &pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
	if (!pDataDir->VirtualAddress)
	{
		return true;
	}

	BYTE* pStart = (BYTE*)pDosHeader;
	auto pExceptionDir = (IMAGE_RUNTIME_FUNCTION_ENTRY*)(pStart + RVAToFileOffset(pNtHeader, pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress));
	for (int x = 0; x < pDataDir->Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY); ++x)
	{
		if (pExceptionDir[x].BeginAddress > adjAboveVA)
		{
			pExceptionDir[x].BeginAddress += dwAdjVA;
		}
		if (pExceptionDir[x].EndAddress > adjAboveVA)
		{
			pExceptionDir[x].EndAddress += dwAdjVA;
		}
		if (pExceptionDir[x].UnwindInfoAddress > adjAboveVA)
		{
			pExceptionDir[x].UnwindInfoAddress += dwAdjVA;
		}
	}

	return true;
}

static inline bool AdjustBaseReloc(IMAGE_DOS_HEADER* pDosHeader, DWORD dwAdjVA, DWORD dwAdjRaw, DWORD adjAboveVA, DWORD adjAboveRawPtr)
{
	typedef struct BASE_RELOCATION_BLOCK
	{
		DWORD PageAddress;
		DWORD BlockSize;
	} BASE_RELOCATION_BLOCK, * PBASE_RELOCATION_BLOCK;

	typedef struct BASE_RELOCATION_ENTRY
	{
		USHORT Offset : 12;
		USHORT Type : 4;
	} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

	IMAGE_NT_HEADERS* pNtHeader = NULL;
	IMAGE_OPTIONAL_HEADER* pOptHeader = NULL;
	if (!GetPtrs((BYTE*)pDosHeader, NULL, &pNtHeader, &pOptHeader))
	{
		return false;
	}

	IMAGE_DATA_DIRECTORY* pDataDir = &pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	if (!pDataDir->VirtualAddress)
	{
		return true;
	}

	BYTE* pStart = (BYTE*)pDosHeader;
	auto pBaseReloc = (IMAGE_BASE_RELOCATION*)(pStart + RVAToFileOffset(pNtHeader, pDataDir->VirtualAddress));

	while (pBaseReloc->VirtualAddress)
	{
		pBaseReloc = (IMAGE_BASE_RELOCATION*)((BYTE*)pBaseReloc + pBaseReloc->SizeOfBlock);
		if (pBaseReloc->VirtualAddress > adjAboveVA)
		{
			pBaseReloc->VirtualAddress += dwAdjVA;
		}
	}

	IMAGE_SECTION_HEADER* pSection = IMAGE_FIRST_SECTION(pNtHeader);
	for (int i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++)
	{
		BYTE* relocSectionName = (BYTE*)".reloc";
		if (memcmp(pSection->Name, relocSectionName, 5) != 0)
		{
			pSection++;
			continue;
		}

		DWORD relocationOffset = 0;
		DWORD sourceRelocationTableRaw = pSection->PointerToRawData;
		while (relocationOffset < pDataDir->Size)
		{
			PBASE_RELOCATION_BLOCK relocationBlock = (PBASE_RELOCATION_BLOCK)(pStart + sourceRelocationTableRaw + relocationOffset);
			relocationOffset += sizeof(BASE_RELOCATION_BLOCK);
			DWORD relocationEntryCount = (relocationBlock->BlockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY);
			PBASE_RELOCATION_ENTRY relocationEntries = (PBASE_RELOCATION_ENTRY)(pStart + sourceRelocationTableRaw + relocationOffset);

			for (DWORD y = 0; y < relocationEntryCount; y++)
			{
				relocationOffset += sizeof(BASE_RELOCATION_ENTRY);

				if (relocationEntries[y].Type == 0)
				{
					continue;
				}

				DWORD patchAddress = RVAToFileOffset(pNtHeader, relocationBlock->PageAddress + relocationEntries[y].Offset);
				uintptr_t* patchedBuffer = (uintptr_t*)(pStart + patchAddress);
				if (*patchedBuffer - pOptHeader->ImageBase > adjAboveVA)
				{
					*patchedBuffer += dwAdjVA;
				}
				/*if(*patchedBuffer)

				ReadProcessMemory(destProcess, (LPCVOID)((DWORD)destImageBase + patchAddress), &patchedBuffer, sizeof(DWORD), &bytesRead);
				patchedBuffer += deltaImageBase;

				WriteProcessMemory(destProcess, (PVOID)((DWORD)destImageBase + patchAddress), &patchedBuffer, sizeof(DWORD), fileBytesRead);
				int a = GetLastError();*/
			}
		}
	}

	return true;
}

static inline bool AdjustDebug(IMAGE_DOS_HEADER* pDosHeader, DWORD dwAdjVA, DWORD dwAdjRaw, DWORD adjAboveVA, DWORD adjAboveRawPtr)
{
	IMAGE_NT_HEADERS* pNtHeader = NULL;
	IMAGE_OPTIONAL_HEADER* pOptHeader = NULL;
	if (!GetPtrs((BYTE*)pDosHeader, NULL, &pNtHeader, &pOptHeader))
	{
		return false;
	}

	IMAGE_DATA_DIRECTORY* pDataDir = &pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
	if (!pDataDir->VirtualAddress)
	{
		return true;
	}

	BYTE* pStart = (BYTE*)pDosHeader;
	auto pDebugDir = (IMAGE_DEBUG_DIRECTORY*)(pStart + RVAToFileOffset(pNtHeader, pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress));
	if (pDebugDir->AddressOfRawData > adjAboveVA)
	{
		pDebugDir->AddressOfRawData += dwAdjVA;
	}
	if (pDebugDir->PointerToRawData > adjAboveRawPtr)
	{
		pDebugDir->PointerToRawData += dwAdjRaw;
	}
}

static inline bool AdjustLoadConfig(IMAGE_DOS_HEADER* pDosHeader, DWORD dwAdjVA, DWORD dwAdjRaw, DWORD adjAboveVA, DWORD adjAboveRawPtr)
{
	IMAGE_NT_HEADERS* pNtHeader = NULL;
	IMAGE_OPTIONAL_HEADER* pOptHeader = NULL;
	if (!GetPtrs((BYTE*)pDosHeader, NULL, &pNtHeader, &pOptHeader))
	{
		return false;
	}

	IMAGE_DATA_DIRECTORY* pDataDir = &pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
	if (!pDataDir->VirtualAddress)
	{
		return true;
	}

	BYTE* pStart = (BYTE*)pDosHeader;
	auto pLoadConfigDir = (IMAGE_LOAD_CONFIG_DIRECTORY*)(pStart + RVAToFileOffset(pNtHeader, pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress));
	if (pLoadConfigDir->SecurityCookie - pOptHeader->ImageBase > adjAboveVA)
	{
		pLoadConfigDir->SecurityCookie += dwAdjVA;
	}

	if (pLoadConfigDir->GuardCFCheckFunctionPointer - pOptHeader->ImageBase > adjAboveVA)
	{
		pLoadConfigDir->GuardCFCheckFunctionPointer += dwAdjVA;
	}

	if (pLoadConfigDir->GuardCFDispatchFunctionPointer - pOptHeader->ImageBase > adjAboveVA)
	{
		pLoadConfigDir->GuardCFDispatchFunctionPointer += dwAdjVA;
	}

	uintptr_t* pTmp = (uintptr_t*)(pStart + RVAToFileOffset(pNtHeader, pLoadConfigDir->GuardCFCheckFunctionPointer - pOptHeader->ImageBase));
	for (size_t x = 0; x < 0x100 / sizeof(void*); ++x, ++pTmp)
	{
		if (!*pTmp)
		{
			continue;
		}

		DWORD val = *pTmp - pOptHeader->ImageBase;
		if (RVAToFileOffset(pNtHeader, val) && val > adjAboveVA)
		{
			*pTmp += dwAdjVA;
		}
	}

	pTmp = (uintptr_t*)(pStart + RVAToFileOffset(pNtHeader, pLoadConfigDir->GuardCFDispatchFunctionPointer - pOptHeader->ImageBase));
	for (size_t x = 0; x < 0x100 / sizeof(void*); ++x, ++pTmp)
	{
		if (!*pTmp)
		{
			continue;
		}

		DWORD val = *pTmp - pOptHeader->ImageBase;
		if (RVAToFileOffset(pNtHeader, val) && val > adjAboveVA)
		{
			*pTmp += dwAdjVA;
		}
	}
}

/// <summary>
/// Update the address for all data directories and their specific structures.
/// </summary>
/// <param name="pDosHeader">Pointer to the DOS header.</param>
/// <param name="dwAdjVA">Amount to adjust VAs by.</param>
/// <param name="dwAdjRaw">Amount to adjust raw pointers by.</param>
/// <param name="adjAboveVA">Any VA above this will be adjusted.</param>
/// <param name="adjAboveRawPtr">Any raw pointer above this will be adjusted.</param>
/// <returns>Returns true on success, false otherwise.</returns>
bool AdjustDataDirectories(IMAGE_DOS_HEADER* pDosHeader, DWORD dwAdjVA, DWORD dwAdjRaw, DWORD adjAboveVA, DWORD adjAboveRawPtr)
{
	IMAGE_OPTIONAL_HEADER* pOptHeader = NULL;
	if (!GetPtrs((BYTE*)pDosHeader, NULL, NULL, &pOptHeader))
	{
		return false;
	}

	// Update directory addresses.
	IMAGE_DATA_DIRECTORY* pDataDir = pOptHeader->DataDirectory;
	for (BYTE bDirIndex = 0; bDirIndex < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; ++bDirIndex)
	{
		// Check for empty entry.
		if (!pDataDir[bDirIndex].VirtualAddress)
		{
			continue;
		}

		if (pDataDir[bDirIndex].VirtualAddress > adjAboveVA)
		{
			pDataDir[bDirIndex].VirtualAddress += dwAdjVA;
		}
	}

	using func_t = std::function<bool(IMAGE_DOS_HEADER* pDosHeader, DWORD dwAdjVA, DWORD dwAdjRaw, DWORD adjAboveVA, DWORD adjAboveRawPtr)>;
	std::array<func_t, IMAGE_NUMBEROF_DIRECTORY_ENTRIES> funcs = {
		AdjustExports, AdjustImports, AdjustResources, AdjustExceptions, AdjustBaseReloc, AdjustDebug, AdjustLoadConfig
	};

	for (auto f : funcs)
	{
		if (!f)
		{
			continue;
		}

		if (!f(pDosHeader, dwAdjVA, dwAdjRaw, adjAboveVA, adjAboveRawPtr))
		{
			return false;
		}
	}

	return true;
}