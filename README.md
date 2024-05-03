# PESENT

**P**ortable **E**xecutable **S**ection **E**xtender (**N**ot just the **T**ail).

The goal of this project is to create a PoC capable of modifying, and more specifically enlarging, any PE section. The focus is on common PE formats; so it may not work on, for example, .NET.

Say you had a program which you needed to add some data to post-build but before execution. This means you must add the data to the binary on disk. Where would this data go? Unfortunately, simply appending data to the binary isn't good enough since it won't be (fully) loaded into memory. The reason for this is that the data must be within a section to be loaded into memory. Another option is to modify an existing section's data. This works, but you are limited to the current size of that section. Yes, you could make the section very large, but this is wasteful if you don't need the space.

Most post-build section modification projects I've seen either create a new section and append it to the existing sections or they modify the last section. Both situations are similar and trivial, and is almost always all that is needed. However, since I had some time to waste I decided to look into getting around this limitation.

My goal was to be able to create a binary which has a pointer into a section created with `#pragma section(...)`. This section could then be updated post-build with data of any size and at runtime the pointer could be used for direct access to the data.

The following is a technical writeup on extending PE sections as well as some miscellaneous findings. A basic understanding of the layout of the PE header is needed.

## Prelude

* The section headers and section data are separate. The section headers come after the optional header. The section data comes after all of the section headers. The section headers contain "pointers" (they are actually file offsets) and virtual addresses which point into section data.
* When a pointer is mentioned in the context of the PE header, it's a file offset.
* Virtual Addresses (VAs) are used for mapping the file into memory and do not directly correspond with offsets in the file. However, you can obtain a file offset from a virtual address or a relative virtual address.
* Relative Virtual Addresses (RVAs) are relative from the base address the image is loaded at. RVAs point into sections. Because of this, RVAs can be converted to file offsets by subtracting the `VirtualAddress` of the section the RVA points into and adding the section's `PointerToRawData`.
* This diagram of the PE header is great.
  * https://web.archive.org/web/20240301215621/https://upload.wikimedia.org/wikipedia/commons/1/1b/Portable_Executable_32_bit_Structure_in_SVG_fixed.svg
* This MSDN page is a helpful reference.
  * https://learn.microsoft.com/en-us/windows/win32/debug/pe-format

## Extending The Last Section

To extend the last section, it's quite simple. All that needs to be done are some size updates and writing the new data.

* Update the section header's `Misc.VirtualSize` to be the absolute (not aligned) size of the data.
* Set the header's `SizeOfRawData` to the size of the data aligned to `FileAlignment`.
* Set (not increment) the `SizeOfImage` to the sum of the section's `VirtualAddress` and `Misc.VirtualSize` aligned to `SectionAlignment`.
* Write your data at the file offset of this section's data. `PointerToRawData` can be used as the file offset.

That should be everything.

## Appending A New Section

To append a new section everything covered previously is still required, but in addition, we must create a new header. This is where I've seen most projects make a mistake. The section headers come after the optional header and are given a fixed amount of space. In other words, you can't just add a new header. First, you have to make sure there is space for a new header. If there isn't space, you must make space.

We'll assume there is space for our new header for now and deal with creating space later.

First we create the new header.

* This header will be located 0x40 (`IMAGE_SIZEOF_SECTION_HEADER`) bytes after the current last header.
* Set the header's `VirtualAddress` to the sum of the previous section header's `VirtualAddress` and `Misc.VirtualSize` aligned to `SectionAlignment`.
* Set the header's `PointerToRawData` to the next available raw data pointer. This can be calculated with the sum of the previous section's `PointerToRawData` and `SizeOfRawData` aligned with `FileAlignment` (it should already be aligned).
* Set the `Misc.VirtualSize`, `VirtualAddress`, and `SizeOfRawData` as before.
* Set any other needed fields such as the section's `Name` and `Characteristics`.

Finally...

* Update the `SizeOfImage` as done before.
* Increment the `NumberOfSections`.
* Write the data as done before.

With that covered, it's time to take care of the case most projects don't. If there isn't room for the new section header, space must be created. The section headers come after all of the other headers and are before section data, so adding space is fairly easy.

* Ensure that however much space you add, it keeps the `SizeOfHeaders` aligned with `FileAlignment`.
  * If `FileAlignment` is 0x200 and you want to add 0x28 bytes, you must write 0x200 bytes.
* Write empty (zeroed) data after the current headers. The offset to the end of the headers can be obtained with `SizeOfHeaders`.
* Update `SizeOfHeaders` keeping it aligned with `FileAlignment`.
* Update `SizeOfImage` keeping it aligned with `SectionAlignment`.
* Update every section header's `PointerToRawData`. This is done in the same way as the `SizeOf*` fields; by incrementing by how much data was added. The `PointerToRawData` needs to also be aligned to `FileAlignment`.
  * You shouldn't have to manually align this field, as the amount you're incrementing by should be aligned and the existing `PointerToRawData` should already be aligned.
  
For a full implementation of appending a new section, see [`AppendSection()` and `AddSectionHeaderSpace()` in Extras.hpp](PESENT/Extras.hpp).

### Bug

Currently there is a, very unlikely to be encountered, bug. This bug occurs when the `SizeOfHeaders` aligned with `SectionAlignment` is greater than `SectionAlignment`. The reason for this is that, by default, the headers only take up the virtual address range of 0x0000 to 0x1000. However, say you have 100 headers. If this is the case then you need, at least on x64, 0x200 bytes for the DOS, NT, etc. headers, then 0xFA0 bytes for the section headers. When the image is mapped into memory the headers will occupy virtual addresses 0x0000 to 0x2000. This is an issue since the first section is likely mapped to 0x1000. This means we must update all virtual addresses. 

This is the same issue that makes extending a section between other sections so difficult and will be discussed in a moment. We will also implement a fix, just not for this case since it's not likely to be an issue.

## Extending A Section (In The Middle)

Finally, the climax of the story, how can we make a section which is sandwiched between other sections larger? It's not easy, but it's fairly intuitive.

First, it should be noted that we are extending a section, not creating a new one. So we don't need to shuffle section headers around since one should already exist. With that said, after reading this, you should be able to squeeze your own header in there if you want.

> In this scenario we **are** making the section data larger. If you want to set the section data to something which is less than or equal to the size of the current section data, then you don't need to do anything besides replace the data.

As you could imagine, we start by doing the same thing we did when extending the last section. The first difference we have to deal with is instead of appending data to the file, we have to insert more space in the middle. This isn't too bad, just remember to remove the existing data as well; don't just append to what is already there.

Since we're adding additional data somewhere in the middle, we must also update any pointers or virtual addresses which may be affected. The first set of additional work to be done is to update the `VirtualAddress` and `PointerToRawData` fields for all section headers after ours.

For each section (after the one we modified) do the following. This should look familiar.

* Set the `VirtualAddress` to the sum of the previous section's `VirtualAddress` and `Misc.VirtualSize` aligned to `SectionAlignment`.
* Set the `PointerToRawData` to the sum of the previous section's `PointerToRawData` and `SizeOfRawData`.

It is possible for the `SizeOfRawData` and `PointerToRawData` to be zero. This occurs when a section is meant for uninitialized data. This means that updating the `PointerToRawData` is a little bit more complicated since the aforementioned summation is not actually the most correct way to do it. Instead, the `PointerToRawData` should be updated based on the next available pointer. This is done by performing the same calculation as mentioned, however, only if the `SizeOfRawData` and `PointerToRawData` are not zero.

For a full implementation of updating sections, see [UpdateSections() in PEHelpers.hpp](PESENT/PEHelpers.hpp).

This is the point I got stuck at. All of my pointers and VAs were updated but I was still being told the PE was invalid. After a bit of digging, I figured it out and it was quite obvious looking back. In fact, I did see it I just didn't acknowledge it. The issue was hinted at with the section header issue encountered earlier. Remember those sections that are already in the header? Well, they probably aren't there for no reason.

As it turns out, I forgot about data directories. Essentially, there are predefined sections that can exist within a PE. Each directory entry contains a `VirtualAddress`. These data directories are essentially extra PE information. For example, entry index 1's `VirtualAddress` points to an `IMAGE_DIRECTORY_ENTRY_IMPORT` structure which is the import directory. The `VirtualAddress` for each entry is actually an RVA into a section. The import directory is usually in the `.idata` section. What this means is that if the import directory entry's `VirtualAddress` is after our modified section's, then it needs to be updated/incremented.

* For each data directory, update the `VirtualAddress`. For many sections (not all) it points to the base of the section. This value can be incremented by the aligned amount of data added.

If you try and run it now, it may or may not work. The problem now is that while we updated the entries, each entry has it's own special content and format. Some entries have VAs or offsets within them. For example, the resource entry (`IMAGE_RESOURCE_DIRECTORY_ENTRY`) contains `OffsetToData` which also must be updated. This means that for every directory entry you must parse its structure and update anything which needs to be updated. This is a pretty rough task, however, each directory entry should be at a specific index. These indexes can be found within `winnt.h`.

The updating of the directory entries is done in [AdjustDataDirectories() in PEHelpers.hpp](PESENT/PEHelpers.hpp).

Once all of the directory entries are updated, now it should work... usually.

### It doesn't always work.

The PE header has many complex and still undocumented structures especially with contraptions such as .NET. But that's not the biggest problem.

Everything falls apart when the compiler decides to use relative addressing, which isn't affected by relocations which can be updated. More specifically, a problem arises when the offset for the relative addressing goes into what was an executable section past the section being modified. When the section to be modified is enlarged, the offset now points to the wrong location. This can be seen with the target compiled in debug mode which adds the `.msvcjmc` section. In this scenario, the process is created successfully, however, during initialization an attempt is made to access data inside of `.msvcjmc`. When this happens, the offset being accessed is invalid due to the modified section and different virtual addresses and section mappings.

I'm unsure if there is a way around this within the PE header that I'm missing. As far as I know, however, this is a problem created by the compiler which has no easy fix. The only fix I see is disassembling executable sections, looking for instances of relative address usage, and updating them.

## Conclusion

Extending a section which is surrounded by existing sections is an interesting, but ultimately unworthy, task. It presents too many issues and in some cases problems which have no direct solution. In most situations, you're better off simply appending a section to the PE and searching for it manually, as seen in the example program. There are other alternatives but they are mostly irrelevant.

With that said, hopefully this PoC and guide can get you pretty far and if you do encounter any extra "fun" you can figure it out a little faster.

### Before

![alt text](_img/Before.png "Title")

### After

![alt text](_img/After.png "Title")