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

void RelocateRSRC(PBYTE prsrc, PIMAGE_RESOURCE_DIRECTORY pird, LONG Delta)
{
	if(DWORD NumberOfEntries = pird->NumberOfNamedEntries + pird->NumberOfIdEntries)
	{
		PIMAGE_RESOURCE_DIRECTORY_ENTRY pirde = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pird + 1);

		do
		{
			if(pirde->DataIsDirectory)
			{
				RelocateRSRC(prsrc,
					(PIMAGE_RESOURCE_DIRECTORY)(prsrc + pirde->OffsetToDirectory),
					Delta);
			}
			else
			{
				PIMAGE_RESOURCE_DATA_ENTRY data =
					(PIMAGE_RESOURCE_DATA_ENTRY)(prsrc + pirde->OffsetToData);

				data->OffsetToData += Delta;
			}

		} while(pirde++, --NumberOfEntries);
	}
}

/// <summary>
/// Update the address for all data directories and their specific structures.
/// </summary>
/// <param name="pDataDirectory">Pointer to the data directory.</param>
/// <param name="dwAmount">Amount to adjust the addresses by.</param>
/// <param name="adjAnythingAbove">Ajust addresses above this value.</param>
/// <returns>Returns true on success, false otherwise.</returns>
bool AdjustDataDirectories(IMAGE_DOS_HEADER* pDosHeader, DWORD dwAdj, DWORD adjAboveVA, DWORD adjAboveRawPtr)
{
	IMAGE_NT_HEADERS* pNtHeader = NULL;
	IMAGE_OPTIONAL_HEADER* pOptHeader = NULL;
	IMAGE_DATA_DIRECTORY* pDataDirectory = NULL;
	if(!GetPtrs((BYTE*)pDosHeader, NULL, &pNtHeader, &pOptHeader))
	{
		return false;
	}
	pDataDirectory = pOptHeader->DataDirectory;

	if(pDosHeader->e_magic != IMAGE_DOS_SIGNATURE || pNtHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		return false;
	}

	BYTE* pStart = (BYTE*)pDosHeader;

	IMAGE_DATA_DIRECTORY* pDataDir = pOptHeader->DataDirectory;
	for(BYTE bDirIndex = 0; bDirIndex < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; ++bDirIndex)
	{
		// Check for empty entry.
		if(!pDataDir[bDirIndex].VirtualAddress)
		{
			continue;
		}

		if(pDataDir[bDirIndex].VirtualAddress > adjAboveVA)
		{
			pDataDir[bDirIndex].VirtualAddress += dwAdj;
		}

		// Directory specific updates...
		if(IMAGE_DIRECTORY_ENTRY_EXPORT == bDirIndex)
		{
			auto pExportDir = (IMAGE_EXPORT_DIRECTORY*)(pStart + RVAToFileOffset(pNtHeader, pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress));
			if(pExportDir->AddressOfFunctions > adjAboveVA)
			{
				pExportDir->AddressOfFunctions += dwAdj;
			}
			if(pExportDir->AddressOfNames > adjAboveVA)
			{
				pExportDir->AddressOfNames += dwAdj;
			}
			if(pExportDir->AddressOfNameOrdinals > adjAboveVA)
			{
				pExportDir->AddressOfNameOrdinals += dwAdj;
			}
		}
		else if(IMAGE_DIRECTORY_ENTRY_IMPORT == bDirIndex)
		{
			auto pImportDir = (IMAGE_IMPORT_DESCRIPTOR*)(pStart + RVAToFileOffset(pNtHeader, pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress));
			while(pImportDir->Name)
			{
				if(pImportDir->OriginalFirstThunk > adjAboveVA)
				{
					pImportDir->OriginalFirstThunk += dwAdj;
				}
				if(pImportDir->FirstThunk > adjAboveVA)
				{
					pImportDir->FirstThunk += dwAdj;
				}

				++pImportDir;
			}
		}
		else if(IMAGE_DIRECTORY_ENTRY_RESOURCE == bDirIndex)
		{
			IMAGE_DATA_DIRECTORY resourceDirectory = pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];

			// If the resource directory is empty, exit as there are no resources.
			if(resourceDirectory.Size == 0)
			{
				continue;
			}

			// Convert the RVA of the resources to a RAW offset
			uintptr_t resourceBase = RVAToFileOffset(pNtHeader, resourceDirectory.VirtualAddress);
			IMAGE_RESOURCE_DIRECTORY* pResourceDir = (IMAGE_RESOURCE_DIRECTORY*)((uintptr_t)pDosHeader + resourceBase);

			RelocateRSRC((PBYTE)pResourceDir, pResourceDir, dwAdj);
			continue;

			IMAGE_RESOURCE_DIRECTORY* pTypesDirectory = pResourceDir;
			IMAGE_RESOURCE_DIRECTORY_ENTRY* pTypeEntries = (IMAGE_RESOURCE_DIRECTORY_ENTRY*)(pTypesDirectory + 1);

			for(uintptr_t ti = 0; ti < pTypesDirectory->NumberOfNamedEntries + pTypesDirectory->NumberOfIdEntries; ti++)
			{
				// Parse Names
				IMAGE_RESOURCE_DIRECTORY_ENTRY* pTypeEntry = &pTypeEntries[ti];
				IMAGE_RESOURCE_DIRECTORY* pNamesDirectory = (IMAGE_RESOURCE_DIRECTORY*)((uintptr_t)pDosHeader + (pTypeEntry->OffsetToDirectory & 0x7FFFFFFF) + resourceBase);
				for(uintptr_t ni = 0; ni < pNamesDirectory->NumberOfNamedEntries + pNamesDirectory->NumberOfIdEntries; ni++)
				{
					// Parse Langs
					IMAGE_RESOURCE_DIRECTORY_ENTRY* pNamesEntries = (IMAGE_RESOURCE_DIRECTORY_ENTRY*)(pNamesDirectory + 1);
					IMAGE_RESOURCE_DIRECTORY_ENTRY* pNameEntry = &pNamesEntries[ni];
					IMAGE_RESOURCE_DIRECTORY* pLangsDirectory = (IMAGE_RESOURCE_DIRECTORY*)((uintptr_t)pDosHeader + (pNameEntry->OffsetToDirectory & 0x7FFFFFFF) + resourceBase);
					for(uintptr_t li = 0; li < pLangsDirectory->NumberOfNamedEntries + pLangsDirectory->NumberOfIdEntries; li++)
					{
						// Parse Data
						IMAGE_RESOURCE_DIRECTORY_ENTRY* pLangsEntries = (IMAGE_RESOURCE_DIRECTORY_ENTRY*)(pLangsDirectory + 1);
						IMAGE_RESOURCE_DIRECTORY_ENTRY* pLangEntry = &pLangsEntries[li];
						IMAGE_RESOURCE_DATA_ENTRY* pDataEntry = (IMAGE_RESOURCE_DATA_ENTRY*)((uintptr_t)pDosHeader + resourceBase + pLangEntry->OffsetToData);

						/*ResourceInfo entry = {};
						entry.Language = pLangsEntries->Id;
						entry.Size = pDataEntry->Size;
						entry.Type = (PIMAGE_RESOURCE_DIR_STRING_U)(pTypeEntry->NameIsString) ? (PIMAGE_RESOURCE_DIR_STRING_U)((uintptr_t)pDosHeader + pTypeEntry->NameOffset + resourceBase) : (PIMAGE_RESOURCE_DIR_STRING_U)(pTypeEntry->Id);
						entry.Name = (PIMAGE_RESOURCE_DIR_STRING_U)(pNameEntry->NameIsString) ? (PIMAGE_RESOURCE_DIR_STRING_U)((uintptr_t)pDosHeader + pNameEntry->NameOffset + resourceBase) : (PIMAGE_RESOURCE_DIR_STRING_U)(pNameEntry->Id);
						entry.data = (BYTE*)pDosHeader + RVAToFileOffset(pNtHeader, pDataEntry->OffsetToData);
						resources.push_back(entry);*/
					}
				}
			}
		}
		//else if(IMAGE_DIRECTORY_ENTRY_EXCEPTION == bDirIndex)
		//{
		//	auto pExceptionDir = (IMAGE_RUNTIME_FUNCTION_ENTRY*)(pStart + RVAToFileOffset(pNtHeader, pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress));
		//	for(int x = 0; x < pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY); ++x)
		//	{
		//		if(pExceptionDir[x].BeginAddress > adjAboveVA)
		//		{
		//			pExceptionDir[x].BeginAddress += dwAdj;
		//		}
		//		if(pExceptionDir[x].EndAddress > adjAboveVA)
		//		{
		//			pExceptionDir[x].EndAddress += dwAdj;
		//		}
		//		if(pExceptionDir[x].UnwindInfoAddress > adjAboveVA)
		//		{
		//			pExceptionDir[x].UnwindInfoAddress += dwAdj;
		//		}
		//	}
		//}
		//else if(IMAGE_DIRECTORY_ENTRY_SECURITY == bDirIndex) {}
		//else if(IMAGE_DIRECTORY_ENTRY_BASERELOC == bDirIndex)
		//{
		//	auto pBaseReloc = (IMAGE_BASE_RELOCATION*)(pStart + RVAToFileOffset(pNtHeader, pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress));
		//	while(pBaseReloc->VirtualAddress)
		//	{
		//		WORD* pReloc = (WORD*)(pBaseReloc + 1);
		//		for(int x = 0; x < (pBaseReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD); ++x)
		//		{
		//			if((*pReloc & 0xFFF) > adjAboveVA)
		//			{
		//				*pReloc += (WORD)dwAdj;
		//			}
		//			++pReloc;
		//		}

		//		pBaseReloc = (IMAGE_BASE_RELOCATION*)((BYTE*)pBaseReloc + pBaseReloc->SizeOfBlock);
		//	}
		//}
		//else if(IMAGE_DIRECTORY_ENTRY_DEBUG == bDirIndex)
		//{
		//	auto pDebugDir = (IMAGE_DEBUG_DIRECTORY*)(pStart + RVAToFileOffset(pNtHeader, pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress));
		//	if(pDebugDir->AddressOfRawData > adjAboveVA)
		//	{
		//		pDebugDir->AddressOfRawData += dwAdj;
		//	}
		//}
		//else if(IMAGE_DIRECTORY_ENTRY_ARCHITECTURE == bDirIndex) {}
		//else if(IMAGE_DIRECTORY_ENTRY_GLOBALPTR == bDirIndex) {}
		//else if(IMAGE_DIRECTORY_ENTRY_TLS == bDirIndex)
		//{
		//	auto pTlsDir = (IMAGE_TLS_DIRECTORY*)(pStart + RVAToFileOffset(pNtHeader, pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress));
		//	if(pTlsDir->AddressOfCallBacks > adjAboveVA)
		//	{
		//		pTlsDir->AddressOfCallBacks += dwAdj;
		//	}
		//}
		//else if(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG == bDirIndex)
		//{
		//	auto pLoadConfigDir = (IMAGE_LOAD_CONFIG_DIRECTORY*)(pStart + RVAToFileOffset(pNtHeader, pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress));
		//	if(pLoadConfigDir->SecurityCookie > adjAboveVA)
		//	{
		//		pLoadConfigDir->SecurityCookie += dwAdj;
		//	}
		//	if(pLoadConfigDir->SEHandlerTable > adjAboveVA)
		//	{
		//		pLoadConfigDir->SEHandlerTable += dwAdj;
		//	}
		//	if(pLoadConfigDir->GuardCFCheckFunctionPointer > adjAboveVA)
		//	{
		//		pLoadConfigDir->GuardCFCheckFunctionPointer += dwAdj;
		//	}
		//	if(pLoadConfigDir->GuardCFFunctionTable > adjAboveVA)
		//	{
		//		pLoadConfigDir->GuardCFFunctionTable += dwAdj;
		//	}
		//	if(pLoadConfigDir->GuardCFFunctionCount > adjAboveVA)
		//	{
		//		pLoadConfigDir->GuardCFFunctionCount += dwAdj;
		//	}

		//	DWORD* pLockPrefixTable = (DWORD*)(pStart + RVAToFileOffset(pNtHeader, pLoadConfigDir->LockPrefixTable));
		//	for(int x = 0; pLockPrefixTable[x]; ++x)
		//	{
		//		if(pLockPrefixTable[x] > adjAboveVA)
		//		{
		//			pLockPrefixTable[x] += dwAdj;
		//		}
		//	}

		//	DWORD* pSeHandlerTable = (DWORD*)(pStart + RVAToFileOffset(pNtHeader, pLoadConfigDir->SEHandlerTable));
		//	for(int x = 0; pSeHandlerTable[x]; ++x)
		//	{
		//		if(pSeHandlerTable[x] > adjAboveVA)
		//		{
		//			pSeHandlerTable[x] += dwAdj;
		//		}
		//	}

		//	DWORD* pGuardCfFunctionTable = (DWORD*)(pStart + RVAToFileOffset(pNtHeader, pLoadConfigDir->GuardCFFunctionTable));
		//	for(int x = 0; pGuardCfFunctionTable[x]; ++x)
		//	{
		//		if(pGuardCfFunctionTable[x] > adjAboveVA)
		//		{
		//			pGuardCfFunctionTable[x] += dwAdj;
		//		}
		//	}

		//	if(pLoadConfigDir->GuardCFCheckFunctionPointer > adjAboveVA)
		//	{
		//		pLoadConfigDir->GuardCFCheckFunctionPointer += dwAdj;
		//	}

		//	if(pLoadConfigDir->GuardCFDispatchFunctionPointer > adjAboveVA)
		//	{
		//		pLoadConfigDir->GuardCFDispatchFunctionPointer += dwAdj;
		//	}

		//	if(pLoadConfigDir->GuardCFFunctionTable > adjAboveVA)
		//	{
		//		pLoadConfigDir->GuardCFFunctionTable += dwAdj;
		//	}

		//	if(pLoadConfigDir->GuardAddressTakenIatEntryTable > adjAboveVA)
		//	{
		//		pLoadConfigDir->GuardAddressTakenIatEntryTable += dwAdj;
		//	}

		//	if(pLoadConfigDir->GuardLongJumpTargetTable > adjAboveVA)
		//	{
		//		pLoadConfigDir->GuardLongJumpTargetTable += dwAdj;
		//	}
		//}
		//else if(IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT == bDirIndex)
		//{
		//	// This will probably cause issues since WORD vs DWORD and WORD max.
		//	auto pBoundImportDir = (IMAGE_BOUND_IMPORT_DESCRIPTOR*)(pStart + RVAToFileOffset(pNtHeader, pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress));
		//	while(pBoundImportDir->OffsetModuleName)
		//	{
		//		if(pBoundImportDir->OffsetModuleName > adjAboveVA)
		//		{
		//			pBoundImportDir->OffsetModuleName += (WORD)dwAdj;
		//		}
		//		if(pBoundImportDir->TimeDateStamp > adjAboveVA)
		//		{
		//			pBoundImportDir->TimeDateStamp += dwAdj;
		//		}
		//		if(pBoundImportDir->OffsetModuleName > adjAboveVA)
		//		{
		//			pBoundImportDir->OffsetModuleName += (WORD)dwAdj;
		//		}

		//		++pBoundImportDir;
		//	}
		//}
		//else if(IMAGE_DIRECTORY_ENTRY_IAT == bDirIndex)
		//{
		//	auto pIatDir = (IMAGE_THUNK_DATA*)(pStart + RVAToFileOffset(pNtHeader, pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress));
		//	while(pIatDir->u1.AddressOfData)
		//	{
		//		if(pIatDir->u1.AddressOfData > adjAboveVA)
		//		{
		//			pIatDir->u1.AddressOfData += dwAdj;
		//		}

		//		++pIatDir;
		//	}
		//}
		//else if(IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT == bDirIndex)
		//{
		//	auto pDelayImportDir = (IMAGE_DELAYLOAD_DESCRIPTOR*)(pStart + RVAToFileOffset(pNtHeader, pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress));
		//	while(pDelayImportDir->DllNameRVA)
		//	{
		//		if(pDelayImportDir->DllNameRVA > adjAboveVA)
		//		{
		//			pDelayImportDir->DllNameRVA += dwAdj;
		//		}
		//		if(pDelayImportDir->ModuleHandleRVA > adjAboveVA)
		//		{
		//			pDelayImportDir->ModuleHandleRVA += dwAdj;
		//		}
		//		if(pDelayImportDir->ImportAddressTableRVA > adjAboveVA)
		//		{
		//			pDelayImportDir->ImportAddressTableRVA += dwAdj;
		//		}
		//		if(pDelayImportDir->ImportNameTableRVA > adjAboveVA)
		//		{
		//			pDelayImportDir->ImportNameTableRVA += dwAdj;
		//		}
		//		if(pDelayImportDir->BoundImportAddressTableRVA > adjAboveVA)
		//		{
		//			pDelayImportDir->BoundImportAddressTableRVA += dwAdj;
		//		}
		//		if(pDelayImportDir->UnloadInformationTableRVA > adjAboveVA)
		//		{
		//			pDelayImportDir->UnloadInformationTableRVA += dwAdj;
		//		}
		//		if(pDelayImportDir->TimeDateStamp > adjAboveVA)
		//		{
		//			pDelayImportDir->TimeDateStamp += dwAdj;
		//		}

		//		++pDelayImportDir;
		//	}
		//}
		//else if(IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR == bDirIndex)
		//{
		//	// No idea if this is correct.
		//	auto pComDir = (IMAGE_COR20_HEADER*)(pStart + RVAToFileOffset(pNtHeader, pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress));
		//	if(pComDir->MetaData.VirtualAddress > adjAboveVA)
		//	{
		//		pComDir->MetaData.VirtualAddress += dwAdj;
		//	}
		//	if(pComDir->Resources.VirtualAddress > adjAboveVA)
		//	{
		//		pComDir->Resources.VirtualAddress += dwAdj;
		//	}
		//	if(pComDir->StrongNameSignature.VirtualAddress > adjAboveVA)
		//	{
		//		pComDir->StrongNameSignature.VirtualAddress += dwAdj;
		//	}
		//	if(pComDir->CodeManagerTable.VirtualAddress > adjAboveVA)
		//	{
		//		pComDir->CodeManagerTable.VirtualAddress += dwAdj;
		//	}
		//	if(pComDir->VTableFixups.VirtualAddress > adjAboveVA)
		//	{
		//		pComDir->VTableFixups.VirtualAddress += dwAdj;
		//	}
		//	if(pComDir->ExportAddressTableJumps.VirtualAddress > adjAboveVA)
		//	{
		//		pComDir->ExportAddressTableJumps.VirtualAddress += dwAdj;
		//	}
		//	if(pComDir->ManagedNativeHeader.VirtualAddress > adjAboveVA)
		//	{
		//		pComDir->ManagedNativeHeader.VirtualAddress += dwAdj;
		//	}
		//}
	}

	return true;
}