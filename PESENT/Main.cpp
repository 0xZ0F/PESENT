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

std::vector<BYTE> SetSectionData(std::vector<BYTE> peData, const std::vector<BYTE>& newSectionData, std::string sectionName)
{
	/// TODO: Update checksums.
	/// TODO: Modify or zero the rich header.

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

	DWORD dwNewSizeAligned = Align((DWORD)newSectionData.size(), pOptHeader->FileAlignment);
	DWORD dwOriginalSize = pSectionHeader->Misc.VirtualSize;
	DWORD dwOriginalSizeAligned = Align(dwOriginalSize, pOptHeader->SectionAlignment);
	DWORD dwAlignedSizeDiff = dwNewSizeAligned - dwOriginalSizeAligned;

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
	pSectionHeader->Misc.VirtualSize = (DWORD)newSectionData.size();
	pSectionHeader->SizeOfRawData = dwNewSizeAligned;

	// If this is the last section then there's nothing else to do.
	if(wSectionIndex == pNtHeader->FileHeader.NumberOfSections - 1)
	{
		return peData;
	}

	// Update all sections after ours
	if(!UpdateSections(pNtHeader))
	{
		return {};
	}

	// Update all data directories.
	IMAGE_DATA_DIRECTORY* pDataDir = pOptHeader->DataDirectory;
	for(BYTE bDirIndex = 0; bDirIndex < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; ++bDirIndex)
	{
		// Check for empty entry.
		if(!pDataDir[bDirIndex].VirtualAddress)
		{
			continue;
		}

		pDataDir[bDirIndex].VirtualAddress += dwAlignedSizeDiff;

		// Directory specific updates...
		if(IMAGE_DIRECTORY_ENTRY_EXPORT == bDirIndex)
		{
			auto pExportDir = (IMAGE_EXPORT_DIRECTORY*)(peData.data() + RVAToFileOffset(pNtHeader, pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress));
			if(pExportDir->AddressOfFunctions > pSectionHeader->VirtualAddress)
			{
				pExportDir->AddressOfFunctions += dwAlignedSizeDiff;
			}
			if(pExportDir->AddressOfNames > pSectionHeader->VirtualAddress)
			{
				pExportDir->AddressOfNames += dwAlignedSizeDiff;
			}
			if(pExportDir->AddressOfNameOrdinals > pSectionHeader->VirtualAddress)
			{
				pExportDir->AddressOfNameOrdinals += dwAlignedSizeDiff;
			}
		}
		else if(IMAGE_DIRECTORY_ENTRY_IMPORT == bDirIndex)
		{
			auto pImportDir = (IMAGE_IMPORT_DESCRIPTOR*)(peData.data() + RVAToFileOffset(pNtHeader, pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress));
			while(pImportDir->Name)
			{
				if(pImportDir->OriginalFirstThunk > pSectionHeader->VirtualAddress)
				{
					pImportDir->OriginalFirstThunk += dwAlignedSizeDiff;
				}
				if(pImportDir->FirstThunk > pSectionHeader->VirtualAddress)
				{
					pImportDir->FirstThunk += dwAlignedSizeDiff;
				}

				++pImportDir;
			}
		}
		else if(IMAGE_DIRECTORY_ENTRY_RESOURCE == bDirIndex)
		{
			auto pResDir = (IMAGE_RESOURCE_DIRECTORY*)(peData.data() + RVAToFileOffset(pNtHeader, pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress));
			auto pResDirEntry = (IMAGE_RESOURCE_DIRECTORY_ENTRY*)(pResDir + 1);
			for(int x = 0; x < pResDir->NumberOfIdEntries + pResDir->NumberOfNamedEntries; ++x)
			{
				if(pResDirEntry[x].OffsetToData > pSectionHeader->VirtualAddress)
				{
					pResDirEntry[x].OffsetToData += dwAlignedSizeDiff;
				}
			}
		}
		else if(IMAGE_DIRECTORY_ENTRY_EXCEPTION == bDirIndex)
		{
			auto pExceptionDir = (IMAGE_RUNTIME_FUNCTION_ENTRY*)(peData.data() + RVAToFileOffset(pNtHeader, pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress));
			for(int x = 0; x < pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY); ++x)
			{
				if(pExceptionDir[x].BeginAddress > pSectionHeader->VirtualAddress)
				{
					pExceptionDir[x].BeginAddress += dwAlignedSizeDiff;
				}
				if(pExceptionDir[x].EndAddress > pSectionHeader->VirtualAddress)
				{
					pExceptionDir[x].EndAddress += dwAlignedSizeDiff;
				}
				if(pExceptionDir[x].UnwindInfoAddress > pSectionHeader->VirtualAddress)
				{
					pExceptionDir[x].UnwindInfoAddress += dwAlignedSizeDiff;
				}
			}
		}
		else if(IMAGE_DIRECTORY_ENTRY_SECURITY == bDirIndex) {}
		else if(IMAGE_DIRECTORY_ENTRY_BASERELOC == bDirIndex)
		{
			auto pBaseReloc = (IMAGE_BASE_RELOCATION*)(peData.data() + RVAToFileOffset(pNtHeader, pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress));
			while(pBaseReloc->VirtualAddress)
			{
				WORD* pReloc = (WORD*)(pBaseReloc + 1);
				for(int x = 0; x < (pBaseReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD); ++x)
				{
					if((*pReloc & 0xFFF) > pSectionHeader->VirtualAddress)
					{
						*pReloc += (WORD)dwAlignedSizeDiff;
					}
					++pReloc;
				}

				pBaseReloc = (IMAGE_BASE_RELOCATION*)((BYTE*)pBaseReloc + pBaseReloc->SizeOfBlock);
			}
		}
		else if(IMAGE_DIRECTORY_ENTRY_DEBUG == bDirIndex)
		{
			auto pDebugDir = (IMAGE_DEBUG_DIRECTORY*)(peData.data() + RVAToFileOffset(pNtHeader, pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress));
			if(pDebugDir->AddressOfRawData > pSectionHeader->VirtualAddress)
			{
				pDebugDir->AddressOfRawData += dwAlignedSizeDiff;
			}
		}
		else if(IMAGE_DIRECTORY_ENTRY_ARCHITECTURE == bDirIndex) {}
		else if(IMAGE_DIRECTORY_ENTRY_GLOBALPTR == bDirIndex) {}
		else if(IMAGE_DIRECTORY_ENTRY_TLS == bDirIndex)
		{
			auto pTlsDir = (IMAGE_TLS_DIRECTORY*)(peData.data() + RVAToFileOffset(pNtHeader, pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress));
			if(pTlsDir->AddressOfCallBacks > pSectionHeader->VirtualAddress)
			{
				pTlsDir->AddressOfCallBacks += dwAlignedSizeDiff;
			}
		}
		else if(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG == bDirIndex)
		{
			auto pLoadConfigDir = (IMAGE_LOAD_CONFIG_DIRECTORY*)(peData.data() + RVAToFileOffset(pNtHeader, pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress));
			if(pLoadConfigDir->SecurityCookie > pSectionHeader->VirtualAddress)
			{
				pLoadConfigDir->SecurityCookie += dwAlignedSizeDiff;
			}
			if(pLoadConfigDir->SEHandlerTable > pSectionHeader->VirtualAddress)
			{
				pLoadConfigDir->SEHandlerTable += dwAlignedSizeDiff;
			}
			if(pLoadConfigDir->GuardCFCheckFunctionPointer > pSectionHeader->VirtualAddress)
			{
				pLoadConfigDir->GuardCFCheckFunctionPointer += dwAlignedSizeDiff;
			}
			if(pLoadConfigDir->GuardCFFunctionTable > pSectionHeader->VirtualAddress)
			{
				pLoadConfigDir->GuardCFFunctionTable += dwAlignedSizeDiff;
			}
			if(pLoadConfigDir->GuardCFFunctionCount > pSectionHeader->VirtualAddress)
			{
				pLoadConfigDir->GuardCFFunctionCount += dwAlignedSizeDiff;
			}

			DWORD* pLockPrefixTable = (DWORD*)(peData.data() + RVAToFileOffset(pNtHeader, pLoadConfigDir->LockPrefixTable));
			for(int x = 0; pLockPrefixTable[x]; ++x)
			{
				if(pLockPrefixTable[x] > pSectionHeader->VirtualAddress)
				{
					pLockPrefixTable[x] += dwAlignedSizeDiff;
				}
			}

			DWORD* pSeHandlerTable = (DWORD*)(peData.data() + RVAToFileOffset(pNtHeader, pLoadConfigDir->SEHandlerTable));
			for(int x = 0; pSeHandlerTable[x]; ++x)
			{
				if(pSeHandlerTable[x] > pSectionHeader->VirtualAddress)
				{
					pSeHandlerTable[x] += dwAlignedSizeDiff;
				}
			}

			DWORD* pGuardCfFunctionTable = (DWORD*)(peData.data() + RVAToFileOffset(pNtHeader, pLoadConfigDir->GuardCFFunctionTable));
			for(int x = 0; pGuardCfFunctionTable[x]; ++x)
			{
				if(pGuardCfFunctionTable[x] > pSectionHeader->VirtualAddress)
				{
					pGuardCfFunctionTable[x] += dwAlignedSizeDiff;
				}
			}

			if(pLoadConfigDir->GuardCFCheckFunctionPointer > pSectionHeader->VirtualAddress)
			{
				pLoadConfigDir->GuardCFCheckFunctionPointer += dwAlignedSizeDiff;
			}

			if(pLoadConfigDir->GuardCFDispatchFunctionPointer > pSectionHeader->VirtualAddress)
			{
				pLoadConfigDir->GuardCFDispatchFunctionPointer += dwAlignedSizeDiff;
			}

			if(pLoadConfigDir->GuardCFFunctionTable > pSectionHeader->VirtualAddress)
			{
				pLoadConfigDir->GuardCFFunctionTable += dwAlignedSizeDiff;
			}

			if(pLoadConfigDir->GuardAddressTakenIatEntryTable > pSectionHeader->VirtualAddress)
			{
				pLoadConfigDir->GuardAddressTakenIatEntryTable += dwAlignedSizeDiff;
			}

			if(pLoadConfigDir->GuardLongJumpTargetTable > pSectionHeader->VirtualAddress)
			{
				pLoadConfigDir->GuardLongJumpTargetTable += dwAlignedSizeDiff;
			}
		}
		else if(IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT == bDirIndex)
		{
			// This will probably cause issues since WORD vs DWORD and WORD max.
			auto pBoundImportDir = (IMAGE_BOUND_IMPORT_DESCRIPTOR*)(peData.data() + RVAToFileOffset(pNtHeader, pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress));
			while(pBoundImportDir->OffsetModuleName)
			{
				if(pBoundImportDir->OffsetModuleName > pSectionHeader->VirtualAddress)
				{
					pBoundImportDir->OffsetModuleName += (WORD)dwAlignedSizeDiff;
				}
				if(pBoundImportDir->TimeDateStamp > pSectionHeader->VirtualAddress)
				{
					pBoundImportDir->TimeDateStamp += dwAlignedSizeDiff;
				}
				if(pBoundImportDir->OffsetModuleName > pSectionHeader->VirtualAddress)
				{
					pBoundImportDir->OffsetModuleName += (WORD)dwAlignedSizeDiff;
				}

				++pBoundImportDir;
			}
		}
		else if(IMAGE_DIRECTORY_ENTRY_IAT == bDirIndex)
		{
			auto pIatDir = (IMAGE_THUNK_DATA*)(peData.data() + RVAToFileOffset(pNtHeader, pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress));
			while(pIatDir->u1.AddressOfData)
			{
				if(pIatDir->u1.AddressOfData > pSectionHeader->VirtualAddress)
				{
					pIatDir->u1.AddressOfData += dwAlignedSizeDiff;
				}

				++pIatDir;
			}
		}
		else if(IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT == bDirIndex)
		{
			auto pDelayImportDir = (IMAGE_DELAYLOAD_DESCRIPTOR*)(peData.data() + RVAToFileOffset(pNtHeader, pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress));
			while(pDelayImportDir->DllNameRVA)
			{
				if(pDelayImportDir->DllNameRVA > pSectionHeader->VirtualAddress)
				{
					pDelayImportDir->DllNameRVA += dwAlignedSizeDiff;
				}
				if(pDelayImportDir->ModuleHandleRVA > pSectionHeader->VirtualAddress)
				{
					pDelayImportDir->ModuleHandleRVA += dwAlignedSizeDiff;
				}
				if(pDelayImportDir->ImportAddressTableRVA > pSectionHeader->VirtualAddress)
				{
					pDelayImportDir->ImportAddressTableRVA += dwAlignedSizeDiff;
				}
				if(pDelayImportDir->ImportNameTableRVA > pSectionHeader->VirtualAddress)
				{
					pDelayImportDir->ImportNameTableRVA += dwAlignedSizeDiff;
				}
				if(pDelayImportDir->BoundImportAddressTableRVA > pSectionHeader->VirtualAddress)
				{
					pDelayImportDir->BoundImportAddressTableRVA += dwAlignedSizeDiff;
				}
				if(pDelayImportDir->UnloadInformationTableRVA > pSectionHeader->VirtualAddress)
				{
					pDelayImportDir->UnloadInformationTableRVA += dwAlignedSizeDiff;
				}
				if(pDelayImportDir->TimeDateStamp > pSectionHeader->VirtualAddress)
				{
					pDelayImportDir->TimeDateStamp += dwAlignedSizeDiff;
				}

				++pDelayImportDir;
			}
		}
		else if(IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR == bDirIndex)
		{
			// No idea if this is correct.
			auto pComDir = (IMAGE_COR20_HEADER*)(peData.data() + RVAToFileOffset(pNtHeader, pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress));
			if(pComDir->MetaData.VirtualAddress > pSectionHeader->VirtualAddress)
			{
				pComDir->MetaData.VirtualAddress += dwAlignedSizeDiff;
			}
			if(pComDir->Resources.VirtualAddress > pSectionHeader->VirtualAddress)
			{
				pComDir->Resources.VirtualAddress += dwAlignedSizeDiff;
			}
			if(pComDir->StrongNameSignature.VirtualAddress > pSectionHeader->VirtualAddress)
			{
				pComDir->StrongNameSignature.VirtualAddress += dwAlignedSizeDiff;
			}
			if(pComDir->CodeManagerTable.VirtualAddress > pSectionHeader->VirtualAddress)
			{
				pComDir->CodeManagerTable.VirtualAddress += dwAlignedSizeDiff;
			}
			if(pComDir->VTableFixups.VirtualAddress > pSectionHeader->VirtualAddress)
			{
				pComDir->VTableFixups.VirtualAddress += dwAlignedSizeDiff;
			}
			if(pComDir->ExportAddressTableJumps.VirtualAddress > pSectionHeader->VirtualAddress)
			{
				pComDir->ExportAddressTableJumps.VirtualAddress += dwAlignedSizeDiff;
			}
			if(pComDir->ManagedNativeHeader.VirtualAddress > pSectionHeader->VirtualAddress)
			{
				pComDir->ManagedNativeHeader.VirtualAddress += dwAlignedSizeDiff;
			}
		}
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