/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "NBIOT-RRC-Definitions"
 * 	found in "rrc.asn1"
 * 	`asn1c -fcompound-names -no-gen-example -gen-PER -pdu=RRCConnectionSetup -D src`
 */

#include "SchedulingInfo-NB-r13.h"

/*
 * This type is implemented using NativeEnumerated,
 * so here we adjust the DEF accordingly.
 */
/*
 * This type is implemented using NativeEnumerated,
 * so here we adjust the DEF accordingly.
 */
/*
 * This type is implemented using NativeEnumerated,
 * so here we adjust the DEF accordingly.
 */
static asn_oer_constraints_t asn_OER_type_si_Periodicity_r13_constr_2 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_si_Periodicity_r13_constr_2 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 3,  3,  0,  7 }	/* (0..7) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_type_si_RepetitionPattern_r13_constr_11 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_si_RepetitionPattern_r13_constr_11 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 2,  2,  0,  3 }	/* (0..3) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_type_si_TB_r13_constr_17 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_si_TB_r13_constr_17 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 3,  3,  0,  7 }	/* (0..7) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static const asn_INTEGER_enum_map_t asn_MAP_si_Periodicity_r13_value2enum_2[] = {
	{ 0,	4,	"rf64" },
	{ 1,	5,	"rf128" },
	{ 2,	5,	"rf256" },
	{ 3,	5,	"rf512" },
	{ 4,	6,	"rf1024" },
	{ 5,	6,	"rf2048" },
	{ 6,	6,	"rf4096" },
	{ 7,	5,	"spare" }
};
static const unsigned int asn_MAP_si_Periodicity_r13_enum2value_2[] = {
	4,	/* rf1024(4) */
	1,	/* rf128(1) */
	5,	/* rf2048(5) */
	2,	/* rf256(2) */
	6,	/* rf4096(6) */
	3,	/* rf512(3) */
	0,	/* rf64(0) */
	7	/* spare(7) */
};
static const asn_INTEGER_specifics_t asn_SPC_si_Periodicity_r13_specs_2 = {
	asn_MAP_si_Periodicity_r13_value2enum_2,	/* "tag" => N; sorted by tag */
	asn_MAP_si_Periodicity_r13_enum2value_2,	/* N => "tag"; sorted by N */
	8,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_si_Periodicity_r13_tags_2[] = {
	(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_si_Periodicity_r13_2 = {
	"si-Periodicity-r13",
	"si-Periodicity-r13",
	&asn_OP_NativeEnumerated,
	asn_DEF_si_Periodicity_r13_tags_2,
	sizeof(asn_DEF_si_Periodicity_r13_tags_2)
		/sizeof(asn_DEF_si_Periodicity_r13_tags_2[0]) - 1, /* 1 */
	asn_DEF_si_Periodicity_r13_tags_2,	/* Same as above */
	sizeof(asn_DEF_si_Periodicity_r13_tags_2)
		/sizeof(asn_DEF_si_Periodicity_r13_tags_2[0]), /* 2 */
	{ &asn_OER_type_si_Periodicity_r13_constr_2, &asn_PER_type_si_Periodicity_r13_constr_2, NativeEnumerated_constraint },
	0, 0,	/* Defined elsewhere */
	&asn_SPC_si_Periodicity_r13_specs_2	/* Additional specs */
};

static const asn_INTEGER_enum_map_t asn_MAP_si_RepetitionPattern_r13_value2enum_11[] = {
	{ 0,	10,	"every2ndRF" },
	{ 1,	10,	"every4thRF" },
	{ 2,	10,	"every8thRF" },
	{ 3,	11,	"every16thRF" }
};
static const unsigned int asn_MAP_si_RepetitionPattern_r13_enum2value_11[] = {
	3,	/* every16thRF(3) */
	0,	/* every2ndRF(0) */
	1,	/* every4thRF(1) */
	2	/* every8thRF(2) */
};
static const asn_INTEGER_specifics_t asn_SPC_si_RepetitionPattern_r13_specs_11 = {
	asn_MAP_si_RepetitionPattern_r13_value2enum_11,	/* "tag" => N; sorted by tag */
	asn_MAP_si_RepetitionPattern_r13_enum2value_11,	/* N => "tag"; sorted by N */
	4,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_si_RepetitionPattern_r13_tags_11[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_si_RepetitionPattern_r13_11 = {
	"si-RepetitionPattern-r13",
	"si-RepetitionPattern-r13",
	&asn_OP_NativeEnumerated,
	asn_DEF_si_RepetitionPattern_r13_tags_11,
	sizeof(asn_DEF_si_RepetitionPattern_r13_tags_11)
		/sizeof(asn_DEF_si_RepetitionPattern_r13_tags_11[0]) - 1, /* 1 */
	asn_DEF_si_RepetitionPattern_r13_tags_11,	/* Same as above */
	sizeof(asn_DEF_si_RepetitionPattern_r13_tags_11)
		/sizeof(asn_DEF_si_RepetitionPattern_r13_tags_11[0]), /* 2 */
	{ &asn_OER_type_si_RepetitionPattern_r13_constr_11, &asn_PER_type_si_RepetitionPattern_r13_constr_11, NativeEnumerated_constraint },
	0, 0,	/* Defined elsewhere */
	&asn_SPC_si_RepetitionPattern_r13_specs_11	/* Additional specs */
};

static const asn_INTEGER_enum_map_t asn_MAP_si_TB_r13_value2enum_17[] = {
	{ 0,	3,	"b56" },
	{ 1,	4,	"b120" },
	{ 2,	4,	"b208" },
	{ 3,	4,	"b256" },
	{ 4,	4,	"b328" },
	{ 5,	4,	"b440" },
	{ 6,	4,	"b552" },
	{ 7,	4,	"b680" }
};
static const unsigned int asn_MAP_si_TB_r13_enum2value_17[] = {
	1,	/* b120(1) */
	2,	/* b208(2) */
	3,	/* b256(3) */
	4,	/* b328(4) */
	5,	/* b440(5) */
	6,	/* b552(6) */
	0,	/* b56(0) */
	7	/* b680(7) */
};
static const asn_INTEGER_specifics_t asn_SPC_si_TB_r13_specs_17 = {
	asn_MAP_si_TB_r13_value2enum_17,	/* "tag" => N; sorted by tag */
	asn_MAP_si_TB_r13_enum2value_17,	/* N => "tag"; sorted by N */
	8,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_si_TB_r13_tags_17[] = {
	(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_si_TB_r13_17 = {
	"si-TB-r13",
	"si-TB-r13",
	&asn_OP_NativeEnumerated,
	asn_DEF_si_TB_r13_tags_17,
	sizeof(asn_DEF_si_TB_r13_tags_17)
		/sizeof(asn_DEF_si_TB_r13_tags_17[0]) - 1, /* 1 */
	asn_DEF_si_TB_r13_tags_17,	/* Same as above */
	sizeof(asn_DEF_si_TB_r13_tags_17)
		/sizeof(asn_DEF_si_TB_r13_tags_17[0]), /* 2 */
	{ &asn_OER_type_si_TB_r13_constr_17, &asn_PER_type_si_TB_r13_constr_17, NativeEnumerated_constraint },
	0, 0,	/* Defined elsewhere */
	&asn_SPC_si_TB_r13_specs_17	/* Additional specs */
};

asn_TYPE_member_t asn_MBR_SchedulingInfo_NB_r13_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct SchedulingInfo_NB_r13, si_Periodicity_r13),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_si_Periodicity_r13_2,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"si-Periodicity-r13"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SchedulingInfo_NB_r13, si_RepetitionPattern_r13),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_si_RepetitionPattern_r13_11,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"si-RepetitionPattern-r13"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SchedulingInfo_NB_r13, sib_MappingInfo_r13),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_SIB_MappingInfo_NB_r13,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"sib-MappingInfo-r13"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SchedulingInfo_NB_r13, si_TB_r13),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_si_TB_r13_17,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"si-TB-r13"
		},
};
static const ber_tlv_tag_t asn_DEF_SchedulingInfo_NB_r13_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_SchedulingInfo_NB_r13_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* si-Periodicity-r13 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* si-RepetitionPattern-r13 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* sib-MappingInfo-r13 */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 } /* si-TB-r13 */
};
asn_SEQUENCE_specifics_t asn_SPC_SchedulingInfo_NB_r13_specs_1 = {
	sizeof(struct SchedulingInfo_NB_r13),
	offsetof(struct SchedulingInfo_NB_r13, _asn_ctx),
	asn_MAP_SchedulingInfo_NB_r13_tag2el_1,
	4,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_SchedulingInfo_NB_r13 = {
	"SchedulingInfo-NB-r13",
	"SchedulingInfo-NB-r13",
	&asn_OP_SEQUENCE,
	asn_DEF_SchedulingInfo_NB_r13_tags_1,
	sizeof(asn_DEF_SchedulingInfo_NB_r13_tags_1)
		/sizeof(asn_DEF_SchedulingInfo_NB_r13_tags_1[0]), /* 1 */
	asn_DEF_SchedulingInfo_NB_r13_tags_1,	/* Same as above */
	sizeof(asn_DEF_SchedulingInfo_NB_r13_tags_1)
		/sizeof(asn_DEF_SchedulingInfo_NB_r13_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_SchedulingInfo_NB_r13_1,
	4,	/* Elements count */
	&asn_SPC_SchedulingInfo_NB_r13_specs_1	/* Additional specs */
};

