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

/// <summary>
/// Update the address for all data directories and their specific structures.
/// </summary>
/// <param name="pDataDirectory">Pointer to the data directory.</param>
/// <param name="dwAmount">Amount to adjust the addresses by.</param>
/// <param name="adjAnythingAbove">Ajust addresses above this value.</param>
/// <returns>Returns true on success, false otherwise.</returns>
bool AdjustDataDirectories(IMAGE_DATA_DIRECTORY* pDataDirectory, DWORD dwAmount, DWORD adjAnythingAbove)
{
	IMAGE_OPTIONAL_HEADER* pOptHeader = CONTAINING_RECORD(pDataDirectory, IMAGE_OPTIONAL_HEADER, DataDirectory);
	IMAGE_NT_HEADERS* pNtHeader = CONTAINING_RECORD(pOptHeader, IMAGE_NT_HEADERS, OptionalHeader);
	IMAGE_DOS_HEADER* pDosHeader = CONTAINING_RECORD(pNtHeader, IMAGE_DOS_HEADER, e_lfanew);
	BYTE* pStart = (BYTE*)pDosHeader;

	IMAGE_DATA_DIRECTORY* pDataDir = pOptHeader->DataDirectory;
	for(BYTE bDirIndex = 0; bDirIndex < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; ++bDirIndex)
	{
		// Check for empty entry.
		if(!pDataDir[bDirIndex].VirtualAddress)
		{
			continue;
		}

		pDataDir[bDirIndex].VirtualAddress += dwAmount;

		// Directory specific updates...
		if(IMAGE_DIRECTORY_ENTRY_EXPORT == bDirIndex)
		{
			auto pExportDir = (IMAGE_EXPORT_DIRECTORY*)(pStart + RVAToFileOffset(pNtHeader, pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress));
			if(pExportDir->AddressOfFunctions > adjAnythingAbove)
			{
				pExportDir->AddressOfFunctions += dwAmount;
			}
			if(pExportDir->AddressOfNames > adjAnythingAbove)
			{
				pExportDir->AddressOfNames += dwAmount;
			}
			if(pExportDir->AddressOfNameOrdinals > adjAnythingAbove)
			{
				pExportDir->AddressOfNameOrdinals += dwAmount;
			}
		}
		else if(IMAGE_DIRECTORY_ENTRY_IMPORT == bDirIndex)
		{
			auto pImportDir = (IMAGE_IMPORT_DESCRIPTOR*)(pStart + RVAToFileOffset(pNtHeader, pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress));
			while(pImportDir->Name)
			{
				if(pImportDir->OriginalFirstThunk > adjAnythingAbove)
				{
					pImportDir->OriginalFirstThunk += dwAmount;
				}
				if(pImportDir->FirstThunk > adjAnythingAbove)
				{
					pImportDir->FirstThunk += dwAmount;
				}

				++pImportDir;
			}
		}
		else if(IMAGE_DIRECTORY_ENTRY_RESOURCE == bDirIndex)
		{
			auto pResDir = (IMAGE_RESOURCE_DIRECTORY*)(pStart + RVAToFileOffset(pNtHeader, pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress));
			auto pResDirEntry = (IMAGE_RESOURCE_DIRECTORY_ENTRY*)(pResDir + 1);
			for(int x = 0; x < pResDir->NumberOfIdEntries + pResDir->NumberOfNamedEntries; ++x)
			{
				if(pResDirEntry[x].OffsetToData > adjAnythingAbove)
				{
					pResDirEntry[x].OffsetToData += dwAmount;
				}
			}
		}
		else if(IMAGE_DIRECTORY_ENTRY_EXCEPTION == bDirIndex)
		{
			auto pExceptionDir = (IMAGE_RUNTIME_FUNCTION_ENTRY*)(pStart + RVAToFileOffset(pNtHeader, pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress));
			for(int x = 0; x < pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY); ++x)
			{
				if(pExceptionDir[x].BeginAddress > adjAnythingAbove)
				{
					pExceptionDir[x].BeginAddress += dwAmount;
				}
				if(pExceptionDir[x].EndAddress > adjAnythingAbove)
				{
					pExceptionDir[x].EndAddress += dwAmount;
				}
				if(pExceptionDir[x].UnwindInfoAddress > adjAnythingAbove)
				{
					pExceptionDir[x].UnwindInfoAddress += dwAmount;
				}
			}
		}
		else if(IMAGE_DIRECTORY_ENTRY_SECURITY == bDirIndex) {}
		else if(IMAGE_DIRECTORY_ENTRY_BASERELOC == bDirIndex)
		{
			auto pBaseReloc = (IMAGE_BASE_RELOCATION*)(pStart + RVAToFileOffset(pNtHeader, pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress));
			while(pBaseReloc->VirtualAddress)
			{
				WORD* pReloc = (WORD*)(pBaseReloc + 1);
				for(int x = 0; x < (pBaseReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD); ++x)
				{
					if((*pReloc & 0xFFF) > adjAnythingAbove)
					{
						*pReloc += (WORD)dwAmount;
					}
					++pReloc;
				}

				pBaseReloc = (IMAGE_BASE_RELOCATION*)((BYTE*)pBaseReloc + pBaseReloc->SizeOfBlock);
			}
		}
		else if(IMAGE_DIRECTORY_ENTRY_DEBUG == bDirIndex)
		{
			auto pDebugDir = (IMAGE_DEBUG_DIRECTORY*)(pStart + RVAToFileOffset(pNtHeader, pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress));
			if(pDebugDir->AddressOfRawData > adjAnythingAbove)
			{
				pDebugDir->AddressOfRawData += dwAmount;
			}
		}
		else if(IMAGE_DIRECTORY_ENTRY_ARCHITECTURE == bDirIndex) {}
		else if(IMAGE_DIRECTORY_ENTRY_GLOBALPTR == bDirIndex) {}
		else if(IMAGE_DIRECTORY_ENTRY_TLS == bDirIndex)
		{
			auto pTlsDir = (IMAGE_TLS_DIRECTORY*)(pStart + RVAToFileOffset(pNtHeader, pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress));
			if(pTlsDir->AddressOfCallBacks > adjAnythingAbove)
			{
				pTlsDir->AddressOfCallBacks += dwAmount;
			}
		}
		else if(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG == bDirIndex)
		{
			auto pLoadConfigDir = (IMAGE_LOAD_CONFIG_DIRECTORY*)(pStart + RVAToFileOffset(pNtHeader, pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress));
			if(pLoadConfigDir->SecurityCookie > adjAnythingAbove)
			{
				pLoadConfigDir->SecurityCookie += dwAmount;
			}
			if(pLoadConfigDir->SEHandlerTable > adjAnythingAbove)
			{
				pLoadConfigDir->SEHandlerTable += dwAmount;
			}
			if(pLoadConfigDir->GuardCFCheckFunctionPointer > adjAnythingAbove)
			{
				pLoadConfigDir->GuardCFCheckFunctionPointer += dwAmount;
			}
			if(pLoadConfigDir->GuardCFFunctionTable > adjAnythingAbove)
			{
				pLoadConfigDir->GuardCFFunctionTable += dwAmount;
			}
			if(pLoadConfigDir->GuardCFFunctionCount > adjAnythingAbove)
			{
				pLoadConfigDir->GuardCFFunctionCount += dwAmount;
			}

			DWORD* pLockPrefixTable = (DWORD*)(pStart + RVAToFileOffset(pNtHeader, pLoadConfigDir->LockPrefixTable));
			for(int x = 0; pLockPrefixTable[x]; ++x)
			{
				if(pLockPrefixTable[x] > adjAnythingAbove)
				{
					pLockPrefixTable[x] += dwAmount;
				}
			}

			DWORD* pSeHandlerTable = (DWORD*)(pStart + RVAToFileOffset(pNtHeader, pLoadConfigDir->SEHandlerTable));
			for(int x = 0; pSeHandlerTable[x]; ++x)
			{
				if(pSeHandlerTable[x] > adjAnythingAbove)
				{
					pSeHandlerTable[x] += dwAmount;
				}
			}

			DWORD* pGuardCfFunctionTable = (DWORD*)(pStart + RVAToFileOffset(pNtHeader, pLoadConfigDir->GuardCFFunctionTable));
			for(int x = 0; pGuardCfFunctionTable[x]; ++x)
			{
				if(pGuardCfFunctionTable[x] > adjAnythingAbove)
				{
					pGuardCfFunctionTable[x] += dwAmount;
				}
			}

			if(pLoadConfigDir->GuardCFCheckFunctionPointer > adjAnythingAbove)
			{
				pLoadConfigDir->GuardCFCheckFunctionPointer += dwAmount;
			}

			if(pLoadConfigDir->GuardCFDispatchFunctionPointer > adjAnythingAbove)
			{
				pLoadConfigDir->GuardCFDispatchFunctionPointer += dwAmount;
			}

			if(pLoadConfigDir->GuardCFFunctionTable > adjAnythingAbove)
			{
				pLoadConfigDir->GuardCFFunctionTable += dwAmount;
			}

			if(pLoadConfigDir->GuardAddressTakenIatEntryTable > adjAnythingAbove)
			{
				pLoadConfigDir->GuardAddressTakenIatEntryTable += dwAmount;
			}

			if(pLoadConfigDir->GuardLongJumpTargetTable > adjAnythingAbove)
			{
				pLoadConfigDir->GuardLongJumpTargetTable += dwAmount;
			}
		}
		else if(IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT == bDirIndex)
		{
			// This will probably cause issues since WORD vs DWORD and WORD max.
			auto pBoundImportDir = (IMAGE_BOUND_IMPORT_DESCRIPTOR*)(pStart + RVAToFileOffset(pNtHeader, pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress));
			while(pBoundImportDir->OffsetModuleName)
			{
				if(pBoundImportDir->OffsetModuleName > adjAnythingAbove)
				{
					pBoundImportDir->OffsetModuleName += (WORD)dwAmount;
				}
				if(pBoundImportDir->TimeDateStamp > adjAnythingAbove)
				{
					pBoundImportDir->TimeDateStamp += dwAmount;
				}
				if(pBoundImportDir->OffsetModuleName > adjAnythingAbove)
				{
					pBoundImportDir->OffsetModuleName += (WORD)dwAmount;
				}

				++pBoundImportDir;
			}
		}
		else if(IMAGE_DIRECTORY_ENTRY_IAT == bDirIndex)
		{
			auto pIatDir = (IMAGE_THUNK_DATA*)(pStart + RVAToFileOffset(pNtHeader, pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress));
			while(pIatDir->u1.AddressOfData)
			{
				if(pIatDir->u1.AddressOfData > adjAnythingAbove)
				{
					pIatDir->u1.AddressOfData += dwAmount;
				}

				++pIatDir;
			}
		}
		else if(IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT == bDirIndex)
		{
			auto pDelayImportDir = (IMAGE_DELAYLOAD_DESCRIPTOR*)(pStart + RVAToFileOffset(pNtHeader, pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress));
			while(pDelayImportDir->DllNameRVA)
			{
				if(pDelayImportDir->DllNameRVA > adjAnythingAbove)
				{
					pDelayImportDir->DllNameRVA += dwAmount;
				}
				if(pDelayImportDir->ModuleHandleRVA > adjAnythingAbove)
				{
					pDelayImportDir->ModuleHandleRVA += dwAmount;
				}
				if(pDelayImportDir->ImportAddressTableRVA > adjAnythingAbove)
				{
					pDelayImportDir->ImportAddressTableRVA += dwAmount;
				}
				if(pDelayImportDir->ImportNameTableRVA > adjAnythingAbove)
				{
					pDelayImportDir->ImportNameTableRVA += dwAmount;
				}
				if(pDelayImportDir->BoundImportAddressTableRVA > adjAnythingAbove)
				{
					pDelayImportDir->BoundImportAddressTableRVA += dwAmount;
				}
				if(pDelayImportDir->UnloadInformationTableRVA > adjAnythingAbove)
				{
					pDelayImportDir->UnloadInformationTableRVA += dwAmount;
				}
				if(pDelayImportDir->TimeDateStamp > adjAnythingAbove)
				{
					pDelayImportDir->TimeDateStamp += dwAmount;
				}

				++pDelayImportDir;
			}
		}
		else if(IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR == bDirIndex)
		{
			// No idea if this is correct.
			auto pComDir = (IMAGE_COR20_HEADER*)(pStart + RVAToFileOffset(pNtHeader, pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress));
			if(pComDir->MetaData.VirtualAddress > adjAnythingAbove)
			{
				pComDir->MetaData.VirtualAddress += dwAmount;
			}
			if(pComDir->Resources.VirtualAddress > adjAnythingAbove)
			{
				pComDir->Resources.VirtualAddress += dwAmount;
			}
			if(pComDir->StrongNameSignature.VirtualAddress > adjAnythingAbove)
			{
				pComDir->StrongNameSignature.VirtualAddress += dwAmount;
			}
			if(pComDir->CodeManagerTable.VirtualAddress > adjAnythingAbove)
			{
				pComDir->CodeManagerTable.VirtualAddress += dwAmount;
			}
			if(pComDir->VTableFixups.VirtualAddress > adjAnythingAbove)
			{
				pComDir->VTableFixups.VirtualAddress += dwAmount;
			}
			if(pComDir->ExportAddressTableJumps.VirtualAddress > adjAnythingAbove)
			{
				pComDir->ExportAddressTableJumps.VirtualAddress += dwAmount;
			}
			if(pComDir->ManagedNativeHeader.VirtualAddress > adjAnythingAbove)
			{
				pComDir->ManagedNativeHeader.VirtualAddress += dwAmount;
			}
		}
	}

	return true;
}