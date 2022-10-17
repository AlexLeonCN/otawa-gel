#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include <gel/error.h>
#include <gel/gel_plugin.h>
#include <gel/gel_elf.h>
#include "gel_mem.h"


/**
#define FORMER_VALUE_AS_ADDEND 1
*/

extern int gel_errno;

/* ensemble des relocations ARM */

#define R_ARM_NONE					0
#define R_ARM_PC24					1
#define R_ARM_ABS32					2
#define R_ARM_REL32					3	/* NOT IMPLEMENTED */
#define R_ARM_PC13					4	/* NOT IMPLEMENTED */
#define R_ARM_ABS16					5	/* NOT IMPLEMENTED */
#define R_ARM_ABS12					6	/* NOT IMPLEMENTED */
#define R_ARM_THM_ABS5				7	/* NOT IMPLEMENTED */
#define R_ARM_ABS8					8	/* NOT IMPLEMENTED */
#define R_ARM_SBREL32				9	/* NOT IMPLEMENTED */
#define R_ARM_THM_PC22				10	/* NOT IMPLEMENTED */
#define R_ARM_THM_PC8				11	/* NOT IMPLEMENTED */
#define R_ARM_BREL_ADJ				12	/* TO FIX: R_ARM_AMP_VCALL9 */
#define R_ARM_SWI24					13
#define R_ARM_THM_SWI8				14
#define R_ARM_XPC25					15
#define R_ARM_THM_XPC22				16
#define R_ARM_TLS_DTPMOD32			17
#define R_ARM_TLS_DTPOFF32			18
#define R_ARM_TLS_TPOFF32			19
#define R_ARM_COPY					20
#define R_ARM_GLOB_DAT				21
#define R_ARM_JUMP_SLOT				22
#define R_ARM_RELATIVE				23
#define R_ARM_PLT32					27
#define R_ARM_CALL					28	/* NOT IMPLEMENTED */
#define R_ARM_JUMP24				29	/* NOT IMPLEMENTED */
#define R_ARM_THM_JUMP24			30	/* NOT IMPLEMENTED */
#define R_ARM_BASE_ABS				31	/* NOT IMPLEMENTED */
#define R_ARM_ALU_PCREL_7_0			32
#define R_ARM_ALU_PCREL_15_8		33
#define R_ARM_ALU_PCREL_23_15		34
#define R_ARM_LDR_SBREL_11_0_NC		35
#define R_ARM_ALU_SBREL_19_12_NC	36
#define R_ARM_ALU_SBREL_27_20_CK	37
#define R_ARM_RELABS32				38	/* NOT IMPLEMENTED */
#define R_ARM_SBREL31				39	/* TO FIX: R_ARM_ROSEGREL32 */
#define R_ARM_V4EX					40	/* NOT IMPLEMENTED */
#define R_ARM_STKCHK				41	/* NOT IMPLEMENTED */
#define R_ARM_THM_STKCHK			42	/* NOT IMPLEMENTED */
#define	R_ARM_MOVW_ABS_NC			43	/* NOT IMPLEMENTED */
#define R_ARM_MOVT_ABS				44	/* NOT IMPLEMENTED */
#define R_ARM_MOVW_PREL_NC			45	/* NOT IMPLEMENTED */
#define R_ARM_MOVT_PREL				46	/* NOT IMPLEMENTED */
#define R_ARM_THM_MOVW_ABS_NC		47
#define R_ARM_THM_MOVT_ABS			48
#define R_ARM_THM_MOVW_PREL_NC		49
#define R_ARM_THM_MOVT_PREL			50
#define R_ARM_THM_JUMP19 			51	/* Static Thumb32 ((S + A) | T) – P */
#define R_ARM_THM_JUMP6				52	/* Static Thumb16 S + A – P */
#define R_ARM_THM_ALU_PREL_11_0 	53	/* Static Thumb32 ((S + A) | T) – Pa */
#define R_ARM_THM_PC12				54	/* Static Thumb32 S + A – Pa */
#define R_ARM_ABS32_NOI				55	/* Static Data S + A */
#define R_ARM_REL32_NOI				56	/* Static Data S + A – P */
#define R_ARM_ALU_PC_G0_NC			57	/* Static ARM ((S + A) | T) – P */
#define R_ARM_ALU_PC_G0				58	/* Static ARM ((S + A) | T) – P */
#define R_ARM_ALU_PC_G1_NC			59	/* Static ARM ((S + A) | T) – P */
#define R_ARM_ALU_PC_G1 			60	/* Static ARM ((S + A) | T) – P */
#define R_ARM_ALU_PC_G2 			61	/* Static ARM ((S + A) | T) – P */
#define R_ARM_LDR_PC_G1 			62	/* Static ARM S + A – P */
#define R_ARM_LDR_PC_G2 			63	/* Static ARM S + A – P */
#define R_ARM_LDRS_PC_G0 			64	/* Static ARM S + A – P */
#define R_ARM_LDRS_PC_G1 			65	/* Static ARM S + A – P */
#define R_ARM_LDRS_PC_G2 			66	/* Static ARM S + A – P */
#define R_ARM_LDC_PC_G0 			67	/* Static ARM S + A – P */
#define R_ARM_LDC_PC_G1 			68	/* Static ARM S + A – P */
#define R_ARM_LDC_PC_G2 			69	/* Static ARM S + A – P */
#define R_ARM_ALU_SB_G0_NC 			70	/* Static ARM ((S + A) | T) – B(S) */
#define R_ARM_ALU_SB_G0 			71	/* Static ARM ((S + A) | T) – B(S) */
#define R_ARM_ALU_SB_G1_NC 			72	/* Static ARM ((S + A) | T) – B(S) */
#define R_ARM_ALU_SB_G1 			73	/* Static ARM ((S + A) | T) – B(S) */
#define R_ARM_ALU_SB_G2 			74	/* Static ARM ((S + A) | T) – B(S) */
#define R_ARM_LDR_SB_G0 			75	/* Static ARM S + A – B(S) */
#define R_ARM_LDR_SB_G1 			76	/* Static ARM S + A – B(S) */
#define R_ARM_LDR_SB_G2 			77	/* Static ARM S + A – B(S) */
#define R_ARM_LDRS_SB_G0 			78	/* Static ARM S + A – B(S) */
#define R_ARM_LDRS_SB_G1 			79	/* Static ARM S + A – B(S) */
#define R_ARM_LDRS_SB_G2 			80	/* Static ARM S + A – B(S) */
#define R_ARM_LDC_SB_G0 			81	/* Static ARM S + A – B(S) */
#define R_ARM_LDC_SB_G1 			82	/* Static ARM S + A – B(S) */
#define R_ARM_LDC_SB_G2 			83	/* Static ARM S + A – B(S) */
#define R_ARM_MOVW_BREL_NC 			84	/* Static ARM ((S + A) | T) – B(S) */
#define R_ARM_MOVT_BREL 			85	/* Static ARM S + A – B(S) */
#define R_ARM_MOVW_BREL				86	/* Static ARM ((S + A) | T) – B(S) */
#define R_ARM_THM_MOVW_BREL_NC 		87	/* Static Thumb32 ((S + A) | T) – B(S) */
#define R_ARM_THM_MOVT_BREL 		88	/* Static Thumb32 S + A – B(S) */
#define R_ARM_THM_MOVW_BREL 		89	/* Static Thumb32 ((S + A) | T) – B(S) */
#define R_ARM_TLS_GOTDESC 			90	/* Static Data */
#define R_ARM_TLS_CALL 				91	/* Static ARM */
#define R_ARM_TLS_DESCSEQ 			92	/* Static ARM */
#define R_ARM_THM_TLS_CALL 			93	/* Static Thumb32 */
#define R_ARM_PLT32_ABS 			94	/* Static Data PLT(S) + A */
#define R_ARM_GOT_ABS 				95	/* Static Data GOT(S) + A */
#define R_ARM_GOT_PREL 				96	/* Static Data GOT(S) + A – P */
#define R_ARM_GOT_BREL12 			97	/* Static ARM GOT(S) + A – GOT_ORG */
#define R_ARM_GOTOFF12 				98	/* Static ARM S + A – GOT_ORG */
#define R_ARM_GOTRELAX 				99	/* Static Miscellaneous */
#define R_ARM_GNU_VTENTRY 			100	/* Deprecated Data ??? */
#define R_ARM_GNU_VTINHERIT 		101	/* Deprecated Data ??? */
#define R_ARM_THM_JUMP11 			102	/* Static Thumb16 S + A – P */
#define R_ARM_THM_JUMP8 			103	/* Static Thumb16 S + A – P */
#define R_ARM_TLS_GD32 				104	/* Static Data GOT(S) + A – P */
#define R_ARM_TLS_LDM32 			105	/* Static Data GOT(S) + A – P */
#define R_ARM_TLS_LDO32 			106	/* Static Data S + A – TLS */
#define R_ARM_TLS_IE32 				107	/* Static Data GOT(S) + A – P */
#define R_ARM_TLS_LE32 				108	/* Static Data S + A – tp */
#define R_ARM_TLS_LDO12 			109	/* Static ARM S + A – TLS */
#define R_ARM_TLS_LE12 Static 		110	/* ARM S + A – tp */
#define R_ARM_TLS_IE12GP 			111	/* Static ARM GOT(S) + A – GOT_ORG */
/*								112-127 R_ARM_PRIVATE_<n> Private (n = 0, 1, ... 15) */
#define R_ARM_ME_TOO 				128	/* Obsolete */
#define R_ARM_THM_TLS_DESCSEQ16 	129	/* Static Thumb16 */
#define R_ARM_THM_TLS_DESCSEQ32 	130	/* Static Thumb32 */
#define R_ARM_THM_GOT_BREL12 		131	/* Static Thumb32 */
#define R_ARM_THM_ALU_ABS_G0_NC		132 /* Static Thumb16 (S + A) | T */
#define R_ARM_THM_ALU_ABS_G1_NC		133 /* Static Thumb16  S + A */
#define R_ARM_THM_ALU_ABS_G2_NC		134 /* Static Thumb16 S + A */
#define R_ARM_THM_ALU_ABS_G3		135	/* Static Thumb16 S + A */
/*								136-159		Reserved for future allocation */
#define R_ARM_IRELATIVE 			160 /* Reserved for future functionality */
/*								161-255		Unallocated */

#define R_ARM_RXPC25				249	/* ARMELF 6 */
#define R_ARM_RSBREL32				250	/* ARMELF 6 */
#define R_ARM_THM_RPC22				251	/* ARMELF 6 */
#define R_ARM_PREL32				252 /* ARMELF 6 */
#define R_ARM_RABS32				253	/* ARMELF 6 */
#define R_ARM_RPC24					254	/* ARMELF 6 */
#define R_ARM_RBASE					255	/* ARMELF 6 */

#define USESYM ((symi.sect == SHN_UNDEF) ? (symi2) : (symi))

/**
 * Fonction permettant de recuperer une entree de relocation de type RELA
 *
 * @param c Le curseur pointant sur l'entree
 * @param rela La structure permettant de recevoir l'entree
 */

static void rela_get(gel_cursor_t *c, Elf32_Rela *rela) {
  rela->r_offset = gel_read_u32(*c);
  rela->r_info = gel_read_u32(*c);
  rela->r_addend = gel_read_s32(*c);
}

/**
 * Fonction permettant de recuperer une entree de relocation de type REL
 *
 * @param c Le curseur pointant sur l'entree
 * @param rela La structure permettant de recevoir l'entree
 */
static void rel_get(gel_cursor_t *c, Elf32_Rel *rel) {
  rel->r_offset = gel_read_u32(*c);
  rel->r_info = gel_read_u32(*c);
}

typedef struct context_t {
	gel_image_info_t ii;		/* image information */
	gel_block_t *b;				/* current block */
	gel_block_info_t bi;		/* current block info */
	gel_file_info_t fi;			/* container file info */
	gel_sect_t *s;				/* current section */
	gel_sect_t *relsect;		/* section being relocated */
	gel_sect_info_t si;			/* current section info */
	gel_sect_t *symtab;			/* symtab section of the current object */
	gel_sect_info_t relsi;		/* info of the section defining the symbol */
	int do_copy;				/* if true, perform copy relocations */
	int flags;					/* linking flags */
	gel_image_t *im;			/* current image */
	gel_hash_t h;				/* current hash table */
	int irelative;				/* record if one irelative warning has already been displayed */

	vaddr_t T;
	vaddr_t A;	/* addend used to compute the new value of the storage unit being relocated. */
	vaddr_t P;	/* displacement of the segment containing the storage unit being relocated */
	vaddr_t S;	/* displacement of the segment indexed by this relocation directive */
	vaddr_t B;	/* displacement of the segment containing the static base */
} context_t;


/**
 * Perform the relocation of an entry.
 * @param ctx	Current context.
 * @param rela	Relocation entry to perform.
 * @return		0 for success, -1 for error.
 */
static int relocate_entry(context_t *ctx, Elf32_Rela rela) {
	gel_sym_t *s1;
	gel_sym_info_t symi;
	gel_sym_t *s2;
	gel_sym_info_t symi2;
	gel_cursor_t bc;
	s32_t res;				/* storage for reloc. calculations (32 bits) */
	s8_t res8; 				/* idem 8bits */
	gel_cursor_t *copy;
	int l;

	// perform only copy if do_copy is enabled
	if ((ELF32_R_TYPE(rela.r_info) != R_ARM_COPY) && ctx->do_copy)
		return 0;

	/* set block cursor */
	if(gel_block2cursor(ctx->b, &bc) == -1)
		return -1;

	/* get symbol associated with relocation entry */
	if(ELF32_R_SYM(rela.r_info) != 0) {	/* not STN_UNDEF */

		s1 = gel_symbyidx(ctx->symtab, ELF32_R_SYM(rela.r_info));
		if (s1 == NULL)
			return -1;		// no error set?
		gel_sym_infos(s1, &symi);

		/* TODO should only be done when st_shndx == SHN_UNDEF? */
		s2 = gel_find_glob_symbol(ctx->im, symi.name);
		if (s2 != NULL) {
			gel_sym_infos(s2, &symi2);
		}
		else
			symi2.sect = SHN_UNDEF;

		if ((symi.sect == SHN_UNDEF) && ((s2 == NULL) || (symi2.sect == SHN_UNDEF))) {
			if (ctx->flags & (GEL_IMAGE_PLTBLOCK_NOW|GEL_IMAGE_PLTBLOCK_LAZY)) {
				if (ELF32_R_TYPE(rela.r_info) == R_ARM_JUMP_SLOT)
					gel_write_block(
						&bc, gel_image_env(ctx->im)->pltblock,
						gel_image_env(ctx->im)->pltblocksize,
						VADDR2RADDR(&ctx->bi, rela.r_offset));
			}
			else {
				gel_errno = GEL_WNONFATAL;
				return 0;
			}
		}

		/* not sure why it is important? */
		if (hash_get(ctx->h, USESYM.name) != NULL) {
			/* this is the source of a COPY relocation, undef s1 */
			symi.sect = SHN_UNDEF;
		}

		/* compute relocation parameters */
		assert(USESYM.blockcont != NULL);
		gel_block_info_t sbi;
		gel_block_infos(USESYM.blockcont, &sbi);
		ctx->B = sbi.base_vaddr;
		ctx->S = (USESYM.vaddr == 0) ? 0 : VADDR2VRELOC(&sbi, USESYM.vaddr);
		ctx->T = ((USESYM.vaddr & 1) && (ELF32_ST_TYPE(USESYM.info) == STT_FUNC)) ? 1 : 0;
		ctx->P = VADDR2VRELOC(&ctx->bi, rela.r_offset);
		ctx->A = rela.r_addend;
	}

	else {								/* in STN_UNDEF */

		/* should be in an executable file */
		if(ctx->fi.type != ET_EXEC) {
			gel_errno = GEL_EFORMAT;
			return -1;
		}

		/* prepare the data */
		s1 = NULL;
		s2 = NULL;
		symi.vaddr = 0;
		symi.sect = SHN_ABS;
		symi2 = symi;

		/* compute relocation parameters */
		ctx->B = 0;
		ctx->S = 0;
		ctx->T = 0;
		ctx->P = rela.r_offset;
		ctx->A = rela.r_addend;
	}

	/* set cursor at the relocation position */
	gel_move_abs(&bc, VRELOC2RADDR(&ctx->bi, ctx->P));
	if(gel_cursor_bounds(&bc) == -1) {
		delete(s1);
		if(ELF32_R_SYM(rela.r_info) == 0)
			return 0;
		gel_errno = GEL_EFORMAT;
		return -1;
	}

	/* read addend from old value */
	gel_move_abs(&bc, VRELOC2RADDR(&ctx->bi, ctx->P));

	/* perform relocation */
	switch(ELF32_R_TYPE(rela.r_info)) {

	case R_ARM_ABS32:
		res = (ctx->S + ctx->A) | ctx->T;
		gel_move_abs(&bc, VRELOC2RADDR(&ctx->bi, ctx->P));
		gel_write_s32(bc, res);
		break;

	case R_ARM_BREL_ADJ:
		res = (ctx->S - ctx->B) + ctx->A;
		gel_move_abs(&bc, VRELOC2RADDR(&ctx->bi, ctx->P));
		gel_write_s32(bc, res);
		break;

/* TODO should we keep this?
case R_ARM_TLS_DTPMOD32:
res = ;
gel_move_abs(&bc, VRELOC2RADDR(&bi,P));
gel_write_s32(bc, res);
break;
case R_ARM_TLS_DTPOFF32:
res = ;
gel_move_abs(&bc, VRELOC2RADDR(&bi,P));
gel_write_s32(bc, res);
break;
case R_ARM_TLS_TPOFF32:
res = ;
gel_move_abs(&bc, VRELOC2RADDR(&bi,P));
gel_write_s32(bc, res);
break;
		 */

	case R_ARM_GLOB_DAT:
		res = (ctx->S + ctx->A) | ctx->T;
		gel_move_abs(&bc, VRELOC2RADDR(&ctx->bi, ctx->P));
		gel_write_s32(bc, res);
		break;

	case R_ARM_JUMP_SLOT:
		if (ctx->flags & GEL_IMAGE_PLTBLOCK_LAZY) {
			gel_write_block(&bc, gel_image_env(ctx->im)->pltblock, gel_image_env(ctx->im)->pltblocksize, VRELOC2RADDR(&ctx->bi, ctx->P));
			break;
		}
		res = (ctx->S + ctx->A) | ctx->T;
		gel_move_abs(&bc, VRELOC2RADDR(&ctx->bi, ctx->P));
		gel_write_s32(bc, res);
		break;

	case R_ARM_RELATIVE:
		res = ctx->B + ctx->A;
		gel_move_abs(&bc, VRELOC2RADDR(&ctx->bi, ctx->P));
		gel_write_s32(bc, res);
		break;

	case R_ARM_COPY:

		/* first pass: add copied symbols to hashtable */
		if (!ctx->do_copy) {
			copy = new(gel_cursor_t);
			if (copy == NULL) {
				gel_errno = GEL_ERESOURCE;
				delete(s1);
				return -1;
			}
			if ((s2 == NULL) || (symi2.sect == SHN_UNDEF)) {
				gel_errno = GEL_EFORMAT;
				delete(s1);
				return -1;
			}
			if (gel_block2cursor(symi2.blockcont, copy) == -1) {
				delete(s1);
				return -1;
			}
			gel_move_abs(copy, VADDR2RADDR(symi2.blockcont, symi2.vaddr));
			hash_put(ctx->h, mystrdup(symi.name), copy);
			gel_replacesym(ctx->im, symi.name, s1);
		}

		/* second pass: copy symbols data */
		else {
			copy = hash_get(ctx->h, symi.name);
			assert(copy != NULL);

			gel_move_abs(&bc, VRELOC2RADDR(&ctx->bi, ctx->P));

			for (l = 0; l < symi2.size; l++) {
				if (gel_cursor_bounds(copy) == -1) {
					gel_errno = GEL_EFORMAT;
					delete(s1);
					return -1;
				}
				res8 = gel_read_s8(*copy);

				if (gel_cursor_bounds(&bc) == -1) {
					gel_errno = GEL_EFORMAT;
					delete(s1);
					return -1;
				}
				gel_write_s8(bc, res8);
			}
		}
		break;

	case R_ARM_IRELATIVE:	/* so ugly? */
		{
			vaddr_t a = ctx->B + ctx->A;
			if(!ctx->irelative) {
				fprintf(stderr, "WARNING: unsupported R_ARM_IRELATIVE relocation: ignored\n");
				ctx->irelative = 1;
			}
		}
		break;

	default:
		//fprintf(stderr, "DEBUG: unknown reloc: %u\n", ELF32_R_TYPE(rela.r_info));
		gel_errno = GEL_EFORMAT;
		delete(s1);
		return -1;
	}

	delete(s1);
	return 0;
}


/**
 * Perform the relocation.
 *
 * @param im 		Image where the relocation is performed.
 * @param h			Hash table containing source addresses.
 * @param flags		Flags.
 * @param do_copy 	Pass number (0: normal, 1: do R_xxx_COPY)
 * @return			Error code.
 */
int real_do_reloc(gel_image_t *im, gel_hash_t h, int flags, int do_copy) {
	context_t ctx;
	gel_cursor_t c				/* cursor for .relX section */
				/*bc*/;				/* cursor for relocated section */
	gel_sym_t *s1, *s2;			/* symbol used by the relocation */
	gel_sym_info_t symi, symi2;	/* symbol info for s1 and s2 */
	Elf32_Rela rela;			/* current RELA entry */
	Elf32_Rel rel;				/* current REL entry */
	int i, j, k, l;

	/* initialize the context */
	ctx.do_copy = do_copy;
	ctx.flags = flags;
	ctx.im = im;
	ctx.h = h;
	ctx.irelative = 0;

	/* for each image member */
	gel_image_infos(im, &ctx.ii);
	for (i = 0; i < ctx.ii.membersnum; i++) {

		/* get block information */
		ctx.b = ctx.ii.members[i];
		gel_block_infos(ctx.b, &ctx.bi);
		if(ctx.bi.container == NULL)	/* stack block or alike */
			continue;
		gel_file_infos(ctx.bi.container, &ctx.fi);

		/* Browse member's sections */
		for (j = 0; j < ctx.fi.sectnum; j++) {

			/* get section information */
			ctx.s = gel_getsectbyidx(ctx.bi.container, j);
			if (ctx.s == NULL) {
				gel_errno = GEL_EFORMAT;
				return -1;
			}
			gel_sect_infos(ctx.s, &ctx.si);

			/* is it relocation? */
			if((ctx.si.type == SHT_RELA) || (ctx.si.type == SHT_REL)) {

				/* C == relocation-section cursor */
				if(gel_sect2cursor(ctx.s, &c) == -1) {
					gel_errno = GEL_EFORMAT;
					return -1;
				}

				/* get symtab associated with relocation section */
				if (ctx.si.link >= ctx.fi.sectnum) {
					gel_errno = GEL_EFORMAT;
					return -1;
				}
				ctx.symtab = gel_getsectbyidx(ctx.bi.container, ctx.si.link);
				if (ctx.symtab == NULL)
					return -1;

				/* get relocated section concerned */
				if (ctx.si.info >= ctx.fi.sectnum) {
					gel_errno = GEL_EFORMAT;
					return -1;
				}
				if (ctx.si.info != SHN_UNDEF) {
					ctx.relsect = gel_getsectbyidx(ctx.bi.container, ctx.si.info);
					if (ctx.relsect == NULL) {
						gel_errno = GEL_EFORMAT;
						return -1;
					}
					gel_sect_infos(ctx.relsect, &ctx.relsi);
				}
				else
					ctx.relsect = NULL;

				/* browse relocation entries */
				for (k = 0; k < ctx.si.size; k += sizeof(Elf32_Rela)) {

					/* read the relocation enty */
					if (ctx.si.type == SHT_REL) {
						rel_get(&c, &rel);
						rela.r_offset = rel.r_offset;
						rela.r_addend = 0;
						rela.r_info = rel.r_info;
					}
					else
						rela_get(&c ,&rela);

					/* perform the relocation */
					int r = relocate_entry(&ctx, rela);
					if(r < 0) {
						gel_errno = GEL_EFORMAT;
						return -1;
					}

				} /* end of this relocation entry*/
			}
		} /* end of this relocation section */
	} /* end of this member file */

	return 0;
}


/**
 * Perform relocation for the given image.
 * @param im	Image to work on.
 * @param flags	Configuration flags.
 */
int do_reloc(gel_image_t *im, int flags) {
	int r;
	gel_hash_t h;

	/* create hash table */
	h = gel_hash_new(211);
	if(h == NULL) {
		gel_errno = GEL_ERESOURCE;
		return -1;
	}

	/* relocation without copy */
	r = real_do_reloc(im, h, flags, 0);
	if (r == -1)
		return r;

	/* relocation with copy */
	r = real_do_reloc(im, h, flags, 1);

	/* release resources */
	hash_free(h);
	return r;
}


/* plugin descriptor */
arch_plugin_t plugin_arch = {
		40,
		1,
		2,	/* stack alignment */
		NULL,
		do_reloc,
		1,
		4096,
};

extern sys_plugin_t null_plugin_sys;
sys_plugin_t *plugin_sys = &null_plugin_sys;
