/*

	MIT License

	Copyright (c) 2021 Kento Oki

	Permission is hereby granted, free of charge, to any person obtaining a copy
	of this software and associated documentation files (the "Software"), to deal
	in the Software without restriction, including without limitation the rights
	to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
	copies of the Software, and to permit persons to whom the Software is
	furnished to do so, subject to the following conditions:

	The above copyright notice and this permission notice shall be included in all
	copies or substantial portions of the Software.

	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
	SOFTWARE.

*/

#pragma once
#include <windows.h>
#include <vector>
#include <DbgHelp.h>

#include "types.hpp"
#include "logger.hpp"
#include "helper.hpp"

#pragma comment(lib, "Dbghelp.lib")

#define MB(x) ((size_t) (x) << 20)

typedef struct _IMAGE_RELOC
{
	WORD	offset : 12;
	WORD	type : 4;
} IMAGE_RELOC, * PIMAGE_RELOC;

static SIZE_T PeLdrImageSize(void* image_base)
{
	return ImageNtHeader(image_base)->OptionalHeader.SizeOfImage;
}

static PVOID PeLdrMapImage(void* image_base, size_t image_size)
{
	const PIMAGE_NT_HEADERS64 pnt_headers = ImageNtHeader(image_base);
	const PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(pnt_headers);

	PVOID mapped_image = VirtualAlloc(
		NULL,
		pnt_headers->OptionalHeader.SizeOfImage,
		MEM_RESERVE | MEM_COMMIT,
		PAGE_EXECUTE_READWRITE);

	if (!mapped_image)
	{
		return NULL;
	}

	memcpy(mapped_image, image_base, image_size);

	for (
		auto i = 0;
		i < pnt_headers->FileHeader.NumberOfSections;
		i++)
	{
		memcpy(
			(void*)((u64)mapped_image + section[i].VirtualAddress),
			(void*)((u64)image_base + section[i].PointerToRawData),
			section[i].SizeOfRawData);
	}

	return mapped_image;
}

// Credit: https://github.com/abhisek/Pe-Loader-Sample/blob/master/src/PeLdr.cpp#L18
static BOOL PeLdrApplyImageRelocations(void* image_base, UINT_PTR iRelocOffset)
{
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS pNtHeaders;
	u64 x;
	DWORD dwTmp;
	PIMAGE_BASE_RELOCATION pBaseReloc;
	PIMAGE_RELOC pReloc;
	ULONG total_count_bytes;

	pDosHeader = (PIMAGE_DOS_HEADER)image_base;
	pNtHeaders = ImageNtHeader(image_base);

	pBaseReloc = (PIMAGE_BASE_RELOCATION)ImageDirectoryEntryToData(pNtHeaders, TRUE, IMAGE_DIRECTORY_ENTRY_BASERELOC, &total_count_bytes);

	if (!pBaseReloc)
	{
		return TRUE;
	}

	while (pBaseReloc->SizeOfBlock) {
		x = (u64)image_base + pBaseReloc->VirtualAddress;
		dwTmp = (pBaseReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOC);
		pReloc = (PIMAGE_RELOC)(((u64)pBaseReloc) + sizeof(IMAGE_BASE_RELOCATION));

		while (dwTmp--) {
			switch (pReloc->type) {
			case IMAGE_REL_BASED_DIR64:
				*((UINT_PTR*)(x + pReloc->offset)) += iRelocOffset;
				break;
			case IMAGE_REL_BASED_HIGHLOW:
				*((DWORD*)(x + pReloc->offset)) += (DWORD)iRelocOffset;
				break;
			case IMAGE_REL_BASED_HIGH:
				*((WORD*)(x + pReloc->offset)) += HIWORD(iRelocOffset);
				break;
			case IMAGE_REL_BASED_LOW:
				*((WORD*)(x + pReloc->offset)) += LOWORD(iRelocOffset);
				break;
			case IMAGE_REL_BASED_ABSOLUTE:
				break;
			default:
				break;
			}

			pReloc += 1;
		}

		pBaseReloc = (PIMAGE_BASE_RELOCATION)(((DWORD)pBaseReloc) + pBaseReloc->SizeOfBlock);
	}

	return TRUE;
}
