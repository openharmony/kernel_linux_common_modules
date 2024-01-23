// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
 */
#include <linux/string.h>
#include <linux/elf.h>
#include <linux/fcntl.h>
#include <linux/slab.h>
#include "exec_signature_info.h"

#if ELF_EXEC_PAGESIZE > PAGE_SIZE
#define ELF_PHNUM_SIZE	ELF_EXEC_PAGESIZE
#else
#define ELF_PHNUM_SIZE	PAGE_SIZE
#endif

#if ELF_PHNUM_SIZE > 65536
#define ELF_PHNUM_MAX_SIZE	65536
#else
#define ELF_PHNUM_MAX_SIZE	ELF_PHNUM_SIZE
#endif

struct elf_info {
	struct elfhdr	elf_ehdr;
	uint16_t	type;
	uint16_t	e_phnum;
	size_t	e_phsize;
	uintptr_t	e_phoff;
};

static int read_elf_info(struct file *file, void *buffer, size_t read_size, loff_t pos)
{
	size_t len;

	len = (size_t)kernel_read(file, buffer, read_size, &pos);
	if (unlikely(len != read_size))
		return -EIO;

	return 0;
}

static uint64_t elf64_get_value(const struct elfhdr *ehdr, uint64_t value)
{
	if (ehdr->e_ident[EI_DATA] == ELFDATA2MSB)
		return be64_to_cpu(value);

	if (ehdr->e_ident[EI_DATA] == ELFDATA2LSB)
		return le64_to_cpu(value);

	return value;
}

static uint32_t elf32_get_value(const struct elfhdr *ehdr, uint32_t value)
{
	if (ehdr->e_ident[EI_DATA] == ELFDATA2MSB)
		return be32_to_cpu(value);

	if (ehdr->e_ident[EI_DATA] == ELFDATA2LSB)
		return le32_to_cpu(value);

	return value;
}

static uint16_t elf16_get_value(const struct elfhdr *ehdr, uint16_t value)
{
	if (ehdr->e_ident[EI_DATA] == ELFDATA2MSB)
		return be16_to_cpu(value);

	if (ehdr->e_ident[EI_DATA] == ELFDATA2LSB)
		return le16_to_cpu(value);

	return value;
}

static int get_elf32_code_segment_count(struct elf32_phdr *elf_phdr,
	struct elf_info *elf_info)
{
	int i;
	int count = 0;
	struct elf32_phdr *phdr_info;
	uint32_t p_flags;

	for (i = 0; i < elf_info->e_phnum; i++) {
		phdr_info = elf_phdr + i;
		p_flags = elf32_get_value(&elf_info->elf_ehdr, phdr_info->p_flags);
		if (!(p_flags & PF_X))
			continue;

		count++;
	}
	return count;
}

static int get_elf32_code_segment(struct elf32_phdr *elf_phdr, struct elf_info *elf_info,
	struct exec_file_signature_info *exec_file_info)
{
	int i;
	struct elf32_phdr *phdr_info;
	uint32_t p_flags;
	uint32_t p_offset;
	uint32_t p_filesz;
	uint32_t p_memsz;
	uint32_t p_addr;

	for (i = 0; i < elf_info->e_phnum; i++) {
		phdr_info = elf_phdr + i;
		p_flags = elf32_get_value(&elf_info->elf_ehdr, phdr_info->p_flags);
		if (!(p_flags & PF_X))
			continue;

		p_offset = elf32_get_value(&elf_info->elf_ehdr, phdr_info->p_offset);
		p_filesz = elf32_get_value(&elf_info->elf_ehdr, phdr_info->p_filesz);
		p_addr = elf32_get_value(&elf_info->elf_ehdr, phdr_info->p_paddr);
		p_memsz = elf32_get_value(&elf_info->elf_ehdr, phdr_info->p_memsz);
		if (p_offset + p_filesz < p_offset || p_addr + p_memsz < p_addr)
			return -ENOEXEC;

		exec_file_info->code_segments[exec_file_info->code_segment_count].file_offset = p_offset;
		exec_file_info->code_segments[exec_file_info->code_segment_count].size = p_filesz;
		exec_file_info->code_segment_count++;
	}
	return 0;
}

static int get_elf64_code_segment_count(struct elf64_phdr *elf_phdr, struct elf_info *elf_info)
{
	int i;
	int count = 0;
	struct elf64_phdr *phdr_info;
	uint32_t p_flags;

	for (i = 0; i < elf_info->e_phnum; i++) {
		phdr_info = elf_phdr + i;
		p_flags = elf32_get_value(&elf_info->elf_ehdr, phdr_info->p_flags);
		if (!(p_flags & PF_X))
			continue;

		count++;
	}
	return count;
}

static int get_elf64_code_segment(struct elf64_phdr *elf_phdr, struct elf_info *elf_info,
	struct exec_file_signature_info *exec_file_info)
{
	int i;
	struct elf64_phdr *phdr_info;
	uint32_t p_flags;
	uint64_t p_offset;
	uint64_t p_filesz;
	uint64_t p_memsz;
	uint64_t p_addr;

	for (i = 0; i < elf_info->e_phnum; i++) {
		phdr_info = elf_phdr + i;
		p_flags = elf32_get_value(&elf_info->elf_ehdr, phdr_info->p_flags);
		if (!(p_flags & PF_X))
			continue;

		p_offset = elf64_get_value(&elf_info->elf_ehdr, phdr_info->p_offset);
		p_filesz = elf64_get_value(&elf_info->elf_ehdr, phdr_info->p_filesz);
		p_addr = elf64_get_value(&elf_info->elf_ehdr, phdr_info->p_paddr);
		p_memsz = elf64_get_value(&elf_info->elf_ehdr, phdr_info->p_memsz);
		if (p_offset + p_filesz < p_offset || p_addr + p_memsz < p_addr)
			return -ENOEXEC;

		exec_file_info->code_segments[exec_file_info->code_segment_count].file_offset = p_offset;
		exec_file_info->code_segments[exec_file_info->code_segment_count].size = p_filesz;
		exec_file_info->code_segment_count++;
	}
	return 0;
}

static int get_elf32_info(struct elfhdr *elf_ehdr, struct elf_info *elf_info)
{
	struct elf32_hdr *elf32_ehdr;
	uint32_t e32_phoff;
	uint32_t e32_phsize;
	uint16_t e_ehsize;

	elf_info->type = ELFCLASS32;
	elf32_ehdr = (struct elf32_hdr *)elf_ehdr;
	e_ehsize = elf16_get_value(elf_ehdr, elf32_ehdr->e_ehsize);
	if (e_ehsize != sizeof(struct elf32_hdr))
		return -ENOEXEC;

	elf_info->e_phnum = elf16_get_value(elf_ehdr, elf32_ehdr->e_phnum);
	e32_phsize = sizeof(struct elf32_phdr) * elf_info->e_phnum;
	if (e32_phsize == 0 || e32_phsize > ELF_PHNUM_MAX_SIZE)
		return -ENOEXEC;

	e32_phoff = elf32_get_value(elf_ehdr, elf32_ehdr->e_phoff);
	if (e32_phoff + e32_phsize < e32_phoff)
		return  -ENOEXEC;

	elf_info->e_phsize = e32_phsize;
	elf_info->e_phoff = e32_phoff;
	return 0;
}

static int get_elf64_info(struct elfhdr *elf_ehdr, struct elf_info *elf_info)
{
	struct elf64_hdr *elf64_ehdr;
	uint64_t e64_phoff;
	uint64_t e64_phsize;
	uint16_t e_ehsize;

	elf_info->type = ELFCLASS64;
	elf64_ehdr = (struct elf64_hdr *)elf_ehdr;
	e_ehsize = elf16_get_value(elf_ehdr, elf64_ehdr->e_ehsize);
	if (e_ehsize != sizeof(struct elf64_hdr))
		return -ENOEXEC;

	elf_info->e_phnum = elf16_get_value(elf_ehdr, elf64_ehdr->e_phnum);
	e64_phsize = sizeof(struct elf64_phdr) * elf_info->e_phnum;
	if (e64_phsize == 0 || e64_phsize > ELF_PHNUM_MAX_SIZE)
		return -ENOEXEC;

	e64_phoff = elf64_get_value(elf_ehdr, elf64_ehdr->e_phoff);
	if (e64_phoff + e64_phsize < e64_phoff)
		return  -ENOEXEC;

	elf_info->e_phsize = e64_phsize;
	elf_info->e_phoff = e64_phoff;
	return 0;
}

static int elf_check_and_get_code_segment_offset(struct file *file, struct elf_info *elf_info)
{
	uint16_t type;
	struct elfhdr *elf_ehdr = &elf_info->elf_ehdr;
	int ret;

	ret = read_elf_info(file, (void *)elf_ehdr, sizeof(struct elfhdr), 0);
	if (ret < 0)
		return ret;

	if (memcmp(elf_ehdr->e_ident, ELFMAG, SELFMAG) != 0)
		return -ENOEXEC;

	type = elf16_get_value(elf_ehdr, elf_ehdr->e_type);
	if (type != ET_EXEC && type != ET_DYN)
		return -ENOEXEC;

	if (elf_ehdr->e_ident[EI_CLASS] == ELFCLASS32)
		return get_elf32_info(elf_ehdr, elf_info);

	if (elf_ehdr->e_ident[EI_CLASS] == ELFCLASS64)
		return get_elf64_info(elf_ehdr, elf_info);

	return -ENOEXEC;
}

static int find_elf_code_segment_info(const char *phdr_info, struct elf_info *elf_info,
	struct exec_file_signature_info **file_info)
{
	int ret;
	size_t size;
	struct exec_file_signature_info *exec_file_info;
	int segment_count;

	if (elf_info->type == ELFCLASS32)
		segment_count = get_elf32_code_segment_count((struct elf32_phdr *)phdr_info, elf_info);
	else
		segment_count = get_elf64_code_segment_count((struct elf64_phdr *)phdr_info, elf_info);

	if (segment_count == 0)
		return -ENOEXEC;

	size = sizeof(struct exec_file_signature_info) + (size_t)segment_count * sizeof(struct exec_segment_info);
	exec_file_info = kzalloc(size, GFP_KERNEL);
	if (exec_file_info == NULL)
		return -ENOMEM;

	exec_file_info->code_segments = (struct exec_segment_info *)((char *)exec_file_info +
									sizeof(struct exec_file_signature_info));
	if (elf_info->type == ELFCLASS32)
		ret = get_elf32_code_segment((struct elf32_phdr *)phdr_info, elf_info, exec_file_info);
	else
		ret = get_elf64_code_segment((struct elf64_phdr *)phdr_info, elf_info, exec_file_info);

	if (ret < 0) {
		kfree(exec_file_info);
		return ret;
	}
	*file_info = exec_file_info;
	return 0;
}

int parse_elf_code_segment_info(struct file *file,
	struct exec_file_signature_info **code_segment_info)
{
	const char *phdr_info;
	struct elf_info elf_info = {0};
	int ret;

	ret = elf_check_and_get_code_segment_offset(file, &elf_info);
	if (ret < 0)
		return ret;

	phdr_info = kzalloc(elf_info.e_phsize, GFP_KERNEL);
	if (phdr_info == NULL)
		return -ENOMEM;

	ret = read_elf_info(file, (void *)phdr_info, elf_info.e_phsize, elf_info.e_phoff);
	if (ret < 0) {
		kfree(phdr_info);
		return ret;
	}

	ret = find_elf_code_segment_info(phdr_info, &elf_info, code_segment_info);
	kfree(phdr_info);
	return ret;
}
