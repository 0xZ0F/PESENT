> A basic understanding of the PE header is assumed.

I was recently looking into post-build configuration for binaries and I was curious about the modification of PE sections. I already knew how to enlarge the last section of the PE, but I wanted more. I didn't like having to search my own binary for data that I put into it. As such, I set out to be able to extend an existing section regardless of it's order or location in the header.

The following is a technical writeup on extending PE sections as well as some interesting findings.

## PESENT

Every project needs a cool name, right? **P**ortable **E**xecutable **S**ection **E**xtender (**N**ot just the **T**ail).

Say you had a executable to which you needed to add some data post-build. This means you must add the data to the binary on disk. Where would this data go? Unfortunately, simply appending data to the binary isn't good enough since it won't be (fully) loaded into memory. The reason for this is that the data must be within a section, as denoted by each section header's virtual address range, to be loaded into memory.

I want to be able to get a pointer to the start of my section, or at the very least, my patched in data. It would be nice to patch in JSON, or some kind of predetermined structure. The following would be ideal.

```c
#pragma section(".custom", read, write)
__declspec(allocate(".custom"))
char g_inSection[1];
```

Now I could access data within my custom section through `g_inSection`. The problem, however, is that this section will have a fixed size likely around 0x512. Sure, you could always make the array really big, but this is an ambiguous solution. The binary may be bigger than needed, it may not be big enough, and will almost certainly result in abnormal entropy.

## Possible Approaches

Before we get to the ideal case, lets look at some alternatives. 

> In all of these scenarios it's assumed that the program is creating the `.custom` section with the `g_inSection` variable as shown previously.

1. The first option is to modify the `.custom` section's data. This works, but you are limited to the current size of that section. Yes, you could make the section very large, but as mentioned previously, this is not good enough.
2. Create a new section and append it to the PE. The program would then need to parse its own PE header and find the section. This is not difficult and is actually quite a nice solution (sample code below). However, I still didn't like searching for my own data.
3. This is the one I was interested in. Create a program which has a pointer into a section created with `#pragma section(...)`. This section could then be updated post-build with data of any size and at runtime the pointer could be used for direct access to the data.

The following is in reference to the second approach. This is how you could search your own PE header, at runtime, for a specific section.
```cpp
IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)GetModuleHandle(NULL);
IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((char*)dosHeader + dosHeader->e_lfanew);
IMAGE_SECTION_HEADER* sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
for(int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
{
    if(strcmp((char*)sectionHeader[i].Name, ".custom") == 0)
    {
        // Section Found
        break;
    }
}
```

Now it's time to start digging.

## Prelude

Here are some bits of information and reminders about the PE header which are relevant.

* The section headers and section data are separate. The section headers come after all other headers (after the optional header). The section data comes after all of the section headers. The section headers contain "pointers" (file offsets) and virtual addresses which point into or map to section data.
* When a pointer is mentioned in the context of the PE header, it's a file offset.
* Virtual Addresses (VAs) are used for mapping the file into memory and do not directly correspond with offsets in the file. However, you can obtain a file offset from a VA or a Relative Virtual Addresses (RVA).
* Relative Virtual Addresses (RVAs) are, unless otherwise stated, relative from the base address the image is loaded at. RVAs point into sections. RVAs can be converted to file offsets by subtracting the `VirtualAddress` of the section the RVA points into and adding the section's `PointerToRawData`.
  * `File Offset = (RVA - Section VA) + Section Pointer To Raw Data` where the "Section" is the section the RVA belongs to.
* This diagram of the PE header is great.
  * <https://web.archive.org/web/20240301215621/https://upload.wikimedia.org/wikipedia/commons/1/1b/Portable_Executable_32_bit_Structure_in_SVG_fixed.svg>
* This MSDN page is a helpful reference.
  * <https://learn.microsoft.com/en-us/windows/win32/debug/pe-format>

Before getting into implementing the ideal solution, it's a good idea to review the other solutions as they are good precursors.

## Extending The Last Section

To extend the data of the last section, it's quite simple. All that needs to be done are some size updates and writing the new data.

* Update the section header's `Misc.VirtualSize` to be the absolute (not aligned) size of the data.
* Set the header's `SizeOfRawData` to the size of the data aligned to `FileAlignment`.
* Set (not increment) the `SizeOfImage` to the sum of the section's `VirtualAddress` and `Misc.VirtualSize` aligned to `SectionAlignment`.
* Write your data at the file offset of this section's data. `PointerToRawData` can be used as the file offset.
  * Pad up to `SizeOfRawData` if needed.

That should be everything.

## Creating and Appending a New Section

To append a new section, everything covered previously is still required, but in addition, we must create a new header. This is where I've seen most projects make a mistake. The section headers come after the optional header and are given a fixed amount of space. Most projects assume that there is space for a new header, however, this is not guaranteed. First, you have to make sure there is space for a new header. If there isn't space, you must make space.

For the moment we'll assume there is space for our new header and deal with creating space later.

### Create The New Header

* The new header will be located after the current last header.
  * This location can be determined by adding 0x40 (`IMAGE_SIZEOF_SECTION_HEADER`) bytes to the starting location of the last header.
* Set the new header's `VirtualAddress` to the sum of the previous section header's `VirtualAddress` and `Misc.VirtualSize` aligned to `SectionAlignment`.
* Set the new header's `PointerToRawData` to the next available pointer to raw data.
  * This can be calculated with the sum of the previous section's `PointerToRawData` and `SizeOfRawData` aligned with `FileAlignment` (the result of this summation should already be aligned).
* Set the `Misc.VirtualSize`, `VirtualAddress`, and `SizeOfRawData` as before.
* Update the `SizeOfImage` as done before.
* Increment the `NumberOfSections`.
* Set any other desired fields such as the section's `Name` and `Characteristics`.
* Write the data as done before.

In most cases, that's all that needs to be done. However, as stated, there may not be space for the new header. If there isn't room for the new section header, space must be created. The section headers come after all of the other headers and are before section data, so adding space is fairly easy.

### Creating Space For New Header (If Needed)

* Ensure that however much space you add, it keeps the `SizeOfHeaders` aligned with `FileAlignment`.
  * If `FileAlignment` is 0x200 and you want to add 0x28 bytes, you must write 0x200 bytes.
* Write empty (zeroed) data after the current headers.
  * The file offset to the end of all the headers can be obtained with `SizeOfHeaders`.
* Update `SizeOfHeaders` keeping it aligned with `FileAlignment`.
* Update `SizeOfImage` keeping it aligned with `SectionAlignment`.
* Update every section header's `PointerToRawData`. This is done in the same way as the `SizeOf*` fields; by incrementing how much data was added. The `PointerToRawData` needs to also be aligned to `FileAlignment`.
  * You shouldn't have to manually align this field, as the amount you're incrementing by should be aligned and the existing `PointerToRawData` should already be aligned.
  
The following is a quick example of how to add header space. Similar code can also be found in the "PESENT" project's source code.
```cpp
std::vector<BYTE> AddSectionHeaderSpace(std::vector<BYTE> data, DWORD dwToAdd)
{
	IMAGE_DOS_HEADER* pDosHeader = NULL;
	IMAGE_NT_HEADERS* pNtHeader = NULL;
	IMAGE_OPTIONAL_HEADER* pOptHeader = NULL;
	IMAGE_FILE_HEADER* pFileHeader = NULL;

  // Helper since I have raw pointers into a vector which may be reallocated.
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

	// Insert data (zeroes) after the headers which is at file offset pOptHeader->SizeOfHeaders.
	data.insert(data.begin() + pOptHeader->SizeOfHeaders, dwToAdd, 0);
	if(!SetPtrs())
	{
		return {};
	}

	// Already aligned (see above).
	pOptHeader->SizeOfHeaders += dwToAdd;
	pOptHeader->SizeOfImage = Align(pOptHeader->SizeOfImage + dwToAdd, pOptHeader->SectionAlignment);

	// Update the PointerToRawData for each section
	IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);
	for(WORD i = 0; i < pNtHeader->FileHeader.NumberOfSections; ++i)
	{
		pSectionHeader[i].PointerToRawData += dwToAdd;
	}

	return data;
}
```

For a full implementation of appending a new section, see `AppendSection()` and `AddSectionHeaderSpace()` in `Extras.hpp`.

### Bug

Currently there is a, very unlikely to be encountered, bug. This bug occurs when the `SizeOfHeaders` aligned with `SectionAlignment` is greater than `SectionAlignment`. The reason for this is that, by default, the headers only take up the virtual address range of 0x0000 to 0x1000. However, say you have 100 headers. If this is the case then you need, at least on x64, 0x200 bytes for the DOS, NT, etc. headers, then 0xFA0 (unaligned) bytes for the section headers. Due to alignment, when the image is mapped into memory the headers will occupy virtual addresses 0x0000 to 0x2000. This is an issue since the first section is likely mapped to 0x1000. This means we must update all virtual addresses. 

This is the same issue that makes extending a section between other sections so difficult and will be discussed in a moment. We will also implement a fix, just not for this case since it's not likely to be an issue. Who needs that many headers?

## Extending A Section (In The Middle)

Finally, the whole point of this thing, how can we make a section which is sandwiched between other sections larger? It's not easy.

First, it should be noted that we are extending a section, not creating a new one. So we don't need to shuffle section headers around since one should already exist. With that said, after reading this, you should be able to squeeze your own header in there if you want.

> In this scenario we **_are_** making the section data larger. If you want to set the section data to something which is less than or equal to the size of the current section data, then you don't need to do anything besides replace the data.

### Familiar Changes

1. As you could imagine, we start by doing the same thing we did when extending the last section. The first difference we have to deal with is instead of appending data to the file, we have to insert more space in the middle. This isn't too different, just remember to remove or overwrite the existing data; don't just append to what is already there.

2. Since we're adding additional data somewhere in the middle, we must also update any pointers or VAs which may be effected. The first set of additional work to be done is to update the `VirtualAddress` and `PointerToRawData` fields for all section headers after ours. For each section (after the one we modified) do the following. This should look familiar.
* Set the `VirtualAddress` to the sum of the previous section's `VirtualAddress` and `Misc.VirtualSize` aligned to `SectionAlignment`.
* Set the `PointerToRawData` to the sum of the previous section's `PointerToRawData` and `SizeOfRawData`.

It is possible for the `SizeOfRawData` and `PointerToRawData` to be zero. This occurs when a section is meant for uninitialized data. This means that updating the `PointerToRawData` is a little bit more complicated since the aforementioned summation is not actually the most correct way to do it. Instead, the `PointerToRawData` should be updated based on the next available pointer. This is done by performing the same calculation as mentioned, however, only if the `SizeOfRawData` and `PointerToRawData` are not zero.

For a full implementation of updating sections, see [UpdateSections() in PEHelpers.hpp](PESENT/PEHelpers.hpp).

### It's Not Working

This is the point I got stuck at. All of my pointers and VAs were updated but I was still being told the PE was invalid. After a bit of digging, I figured it out and it was quite obvious looking back. In fact, I did see it I just didn't acknowledge it. The issue was hinted at with the section header issue encountered earlier when creating new headers. Remember those sections that are already in the header, such as `.text`? Well, they probably aren't there for no reason.

As it turns out, I forgot about data directories. Essentially, there are predefined sections that can exist within a PE. Each directory entry contains a `VirtualAddress`. These data directories are essentially extra PE information. For example, by definition entry index 1's `VirtualAddress` points to an `IMAGE_DIRECTORY_ENTRY_IMPORT` structure which is the import directory.

The `VirtualAddress` for each entry is actually an RVA into a section. The import directory is usually in the `.idata` section. What this means is that if the import directory entry's `VirtualAddress` is after our modified section's, then it needs to be updated/incremented.

3. For each data directory, update the `VirtualAddress`. For many sections (not all) it points to the base of the section. This value can be incremented by the aligned amount of data added.

### It's Still Not Working

If you try and run it now, it may or may not work. The problem now is that while we updated the entries, each entry has it's own special content and format. Some entries have VAs or offsets within them. For example, the resource entry (`IMAGE_RESOURCE_DIRECTORY_ENTRY`) contains `OffsetToData` which also must be updated.

4. This means that for every directory entry you must parse its structure and update anything which needs to be updated. This is a pretty rough task, however, each directory entry should be at a specific index. These indexes can be found within `winnt.h`.

The code for updating the entries is too long to put here. Instead, the updating of some of the directory entries can be found in [AdjustDataDirectories() in PEHelpers.hpp](PESENT/PEHelpers.hpp).

Once all of the directory entries are updated, now it should work... right, Anakin?

> You may also want to update the PE checksums if that's a requirement for your process.

### It Works Sometimes

Although it works on a release version of the `ExampleTarget` project provided on the GitHub repository, it doesn't work for all executables. The example binary only needs adjustments done to it's relocations and resources. However, the PE header has many complex and still undocumented structures especially with contraptions such as .NET. **But that's not the biggest problem.**

Everything falls apart when the compiler decides to use relative addressing, which isn't affected by relocations which can be updated. More specifically, a problem arises when the offset for the relative addressing goes into what was a section past the section being modified. When the section to be modified is enlarged, the offset now points to the wrong location. This can be seen with `ExampleTarget` compiled in debug mode which adds the `.msvcjmc` section. In this scenario, the process is created successfully, however, during initialization to get to our code, an attempt is made to access data inside of `.msvcjmc`. When this happens, a relative offset is used but it's invalid due to the modified section shifting the virtual addresses.

I'm unsure if there is a way around this within the PE header that I'm missing. As far as I know, this is a problem created by the compiler which has no easy fix. The only fix I see is disassembling executable sections, looking for instances of relative address usage, and updating them. I would be very happy if someone could prove me wrong.

## Conclusion

Now I'm the peasant.

Extending a section which is surrounded by existing sections is an interesting, but ultimately unworthy, task. It presents too many issues and in some cases problems which have no direct solution that I'm aware of. In most situations, you're better off simply appending a section to the PE and searching for it manually, as seen in the example program and as mentioned as approach #2. There are other alternatives but they are mostly irrelevant.

With that said, hopefully you learned something and this PoC and guide can get you a little further.