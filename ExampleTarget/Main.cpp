#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include "Windows.h"

#include <iostream>

#define SECTION_TO_MODIFY ".pesent"
#define AMOUNT_OF_SECTION_TO_PRINT 32

#pragma section(SECTION_TO_MODIFY, read, write)
__declspec(allocate(SECTION_TO_MODIFY))
char g_inSection[1];

int main()
{
	printf("ExampleTarget\n");
	printf("Addr g_inSection: %p\n", g_inSection);
	printf("Str g_inSection: %s\n", g_inSection);

	printf("Hex g_inSection: ");
	for(int i = 0; i < AMOUNT_OF_SECTION_TO_PRINT; i++)
	{
		printf("%02X ", g_inSection[i]);
	}
	printf("\n\n");

	// Manually get the section g_inSection is in.
	IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)GetModuleHandle(NULL);
	IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((char*)dosHeader + dosHeader->e_lfanew);
	IMAGE_SECTION_HEADER* sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
	for(int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
	{
		if(strcmp((char*)sectionHeader[i].Name, SECTION_TO_MODIFY) == 0)
		{
			printf("Section\n");
			printf("  VirtualAddress: %p\n", (char*)dosHeader + sectionHeader[i].VirtualAddress);
			printf("  VirtualSize: %X\n", sectionHeader[i].Misc.VirtualSize);
			printf("  PointerToRawData: %X\n", sectionHeader[i].PointerToRawData);
			printf("  SizeOfRawData: %X\n", sectionHeader[i].SizeOfRawData);
			printf("  Characteristics: %X\n", sectionHeader[i].Characteristics);
			break;
		}
	}

	return 0;
}
