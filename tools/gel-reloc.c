/*
 * gel-reloc tool
 * Copyright (c) 2008, IRIT- UPS
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <gel/file.h>
#include <gel/gel.h>
#include <gel/gel_elf.h>
#include <gel/sym.h>

/**
 * Display the help message and exit.
 */
void help(void) {
	printf(
		"SYNTAX: gel-sect <file name>\n"
	);
	exit(1);
}



/**
 * Command entry point.
 */
int main(int argc, char **argv) {
	const char *path;
	gel_file_t *file;
	int opt, i = 0;
	const char *find = NULL;
	const char *name = NULL;
	
	/* Check arguments */
	opterr = 1;
	while((opt = getopt(argc, argv, "h")) != EOF)
		switch(opt) {
		case 'h':
			help();
			/* no break */
		default:
			assert(0);
		}
	if(optind >= argc) {
		fprintf(stderr, "ERROR: a binary file is required !\n");
		help();
		return 1;
	}
	path = argv[optind];
	
	/* open the file */
	file = gel_open(path, "", 0);
	if(file == NULL) {
    	fprintf(stderr, "ERROR: %s\n", gel_strerror());
    	return 2;
  	}

	/* perform the search */
	for(i = 0; i < file->sectnum; i++) {

		/* get the section information */
		gel_sect_info_t info;
		gel_sect_t *sect = gel_getsectbyidx(file, i);
		assert(sect);
		if(gel_sect_infos(sect, &info) < 0) {
			fprintf(stderr, "ERROR: %s\n", gel_strerror());
			return 3;
		}

		/* Is it a relocation? */
		if(info.type == SHT_REL || info.type == SHT_RELA) {
			int is_rela = info.type == SHT_RELA;

			/* open section for symbol names */
			gel_sect_t *symtab = gel_getsectbyidx(file, info.link);
			if(symtab == NULL) {
				fprintf(stderr, "ERROR: cannot find symbol section\n");
				return 3;
			}
			gel_sect_info_t sti;
			if(gel_sect_infos(symtab, &sti) < 0) {
				fprintf(stderr, "ERROR: %s\n", gel_strerror());
				return 3;
			}

			/* open section it applies to */
			gel_sect_t *rsect = gel_getsectbyidx(file, info.info);
			if(rsect == NULL) {
				fprintf(stderr, "ERROR: cannot find relocated section\n");
				return 3;
			}
			gel_sect_info_t ri;
			if(gel_sect_infos(rsect, &ri) < 0) {
				fprintf(stderr, "ERROR: %s\n", gel_strerror());
				return 3;
			}

			/* display information about the section */
			printf("SHT_REL%s %s (symtab=%d - %s, apply=%d - %s)\n",
				is_rela ? "A" : "",
				info.name,
				info.link,
				sti.name,
				info.info,
				ri.name);

			/* get cursor on the section */
			gel_cursor_t c;
			if (gel_sect2cursor(sect, &c) == -1) {
				fprintf(stderr, "ERROR: bad format\n");
				return 3;
			}

			/* read the entries */
			printf("  TYPE   OFFSET   %sSYMBOL\n",
				is_rela ? "ADDEND  " : "");
			while(!gel_cursor_at_end(c)) {

				/* read information */
				Elf32_Rela r;
				r.r_offset = gel_read_s32(c);
				if(gel_cursor_at_end(c)) {
					fprintf(stderr, "ERROR: bad format in relocation entry\n");
					return 4;
				}
				r.r_info = gel_read_u32(c);
				if(is_rela) {
					if(gel_cursor_at_end(c)) {
						fprintf(stderr, "ERROR: bad format in relocation entry\n");
						return 4;
					}
					r.r_addend = gel_read_s32(c);
				}
				else
					r.r_addend = 0;

				/* get symbol name */
				const char *name = "";
				if(ELF32_R_SYM(r.r_info) != 0) {
					gel_sym_t *s = gel_symbyidx(symtab, ELF32_R_SYM(r.r_info));
					if(s == NULL) {
						fprintf(stderr, "ERROR: cannot find relocation symbol\n");
						return 4;
					}
					gel_sym_info_t si;
					gel_sym_infos(s, &si);
					name = si.name;
				}

				/* display information */
				printf("%8d %08x ",
						ELF32_R_TYPE(r.r_info),
						r.r_offset);
				if(is_rela)
					printf("%08x ", r.r_addend);
				printf("%d %s\n", ELF32_R_SYM(r.r_info), name);
			}
		}

	}

	/* cleanup */ 
	gel_close(file);
	return 0;
}
