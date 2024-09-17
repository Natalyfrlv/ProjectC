/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "rrc.asn1"
 * 	`asn1c -fcompound-names -no-gen-example -gen-PER -pdu=RRCConnectionSetup -D src`
 */

#include "DeltaFList-PUCCH.h"

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
/*
 * This type is implemented using NativeEnumerated,
 * so here we adjust the DEF accordingly.
 */
/*
 * This type is implemented using NativeEnumerated,
 * so here we adjust the DEF accordingly.
 */
static asn_oer_constraints_t asn_OER_type_deltaF_PUCCH_Format1_constr_2 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_deltaF_PUCCH_Format1_constr_2 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 2,  2,  0,  2 }	/* (0..2) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_type_deltaF_PUCCH_Format1b_constr_6 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_deltaF_PUCCH_Format1b_constr_6 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 2,  2,  0,  2 }	/* (0..2) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_type_deltaF_PUCCH_Format2_constr_10 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_deltaF_PUCCH_Format2_constr_10 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 2,  2,  0,  3 }	/* (0..3) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_type_deltaF_PUCCH_Format2a_constr_15 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_deltaF_PUCCH_Format2a_constr_15 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 2,  2,  0,  2 }	/* (0..2) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_type_deltaF_PUCCH_Format2b_constr_19 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_deltaF_PUCCH_Format2b_constr_19 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 2,  2,  0,  2 }	/* (0..2) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static const asn_INTEGER_enum_map_t asn_MAP_deltaF_PUCCH_Format1_value2enum_2[] = {
	{ 0,	8,	"deltaF-2" },
	{ 1,	7,	"deltaF0" },
	{ 2,	7,	"deltaF2" }
};
static const unsigned int asn_MAP_deltaF_PUCCH_Format1_enum2value_2[] = {
	0,	/* deltaF-2(0) */
	1,	/* deltaF0(1) */
	2	/* deltaF2(2) */
};
static const asn_INTEGER_specifics_t asn_SPC_deltaF_PUCCH_Format1_specs_2 = {
	asn_MAP_deltaF_PUCCH_Format1_value2enum_2,	/* "tag" => N; sorted by tag */
	asn_MAP_deltaF_PUCCH_Format1_enum2value_2,	/* N => "tag"; sorted by N */
	3,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_deltaF_PUCCH_Format1_tags_2[] = {
	(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_deltaF_PUCCH_Format1_2 = {
	"deltaF-PUCCH-Format1",
	"deltaF-PUCCH-Format1",
	&asn_OP_NativeEnumerated,
	asn_DEF_deltaF_PUCCH_Format1_tags_2,
	sizeof(asn_DEF_deltaF_PUCCH_Format1_tags_2)
		/sizeof(asn_DEF_deltaF_PUCCH_Format1_tags_2[0]) - 1, /* 1 */
	asn_DEF_deltaF_PUCCH_Format1_tags_2,	/* Same as above */
	sizeof(asn_DEF_deltaF_PUCCH_Format1_tags_2)
		/sizeof(asn_DEF_deltaF_PUCCH_Format1_tags_2[0]), /* 2 */
	{ &asn_OER_type_deltaF_PUCCH_Format1_constr_2, &asn_PER_type_deltaF_PUCCH_Format1_constr_2, NativeEnumerated_constraint },
	0, 0,	/* Defined elsewhere */
	&asn_SPC_deltaF_PUCCH_Format1_specs_2	/* Additional specs */
};

static const asn_INTEGER_enum_map_t asn_MAP_deltaF_PUCCH_Format1b_value2enum_6[] = {
	{ 0,	7,	"deltaF1" },
	{ 1,	7,	"deltaF3" },
	{ 2,	7,	"deltaF5" }
};
static const unsigned int asn_MAP_deltaF_PUCCH_Format1b_enum2value_6[] = {
	0,	/* deltaF1(0) */
	1,	/* deltaF3(1) */
	2	/* deltaF5(2) */
};
static const asn_INTEGER_specifics_t asn_SPC_deltaF_PUCCH_Format1b_specs_6 = {
	asn_MAP_deltaF_PUCCH_Format1b_value2enum_6,	/* "tag" => N; sorted by tag */
	asn_MAP_deltaF_PUCCH_Format1b_enum2value_6,	/* N => "tag"; sorted by N */
	3,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_deltaF_PUCCH_Format1b_tags_6[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_deltaF_PUCCH_Format1b_6 = {
	"deltaF-PUCCH-Format1b",
	"deltaF-PUCCH-Format1b",
	&asn_OP_NativeEnumerated,
	asn_DEF_deltaF_PUCCH_Format1b_tags_6,
	sizeof(asn_DEF_deltaF_PUCCH_Format1b_tags_6)
		/sizeof(asn_DEF_deltaF_PUCCH_Format1b_tags_6[0]) - 1, /* 1 */
	asn_DEF_deltaF_PUCCH_Format1b_tags_6,	/* Same as above */
	sizeof(asn_DEF_deltaF_PUCCH_Format1b_tags_6)
		/sizeof(asn_DEF_deltaF_PUCCH_Format1b_tags_6[0]), /* 2 */
	{ &asn_OER_type_deltaF_PUCCH_Format1b_constr_6, &asn_PER_type_deltaF_PUCCH_Format1b_constr_6, NativeEnumerated_constraint },
	0, 0,	/* Defined elsewhere */
	&asn_SPC_deltaF_PUCCH_Format1b_specs_6	/* Additional specs */
};

static const asn_INTEGER_enum_map_t asn_MAP_deltaF_PUCCH_Format2_value2enum_10[] = {
	{ 0,	8,	"deltaF-2" },
	{ 1,	7,	"deltaF0" },
	{ 2,	7,	"deltaF1" },
	{ 3,	7,	"deltaF2" }
};
static const unsigned int asn_MAP_deltaF_PUCCH_Format2_enum2value_10[] = {
	0,	/* deltaF-2(0) */
	1,	/* deltaF0(1) */
	2,	/* deltaF1(2) */
	3	/* deltaF2(3) */
};
static const asn_INTEGER_specifics_t asn_SPC_deltaF_PUCCH_Format2_specs_10 = {
	asn_MAP_deltaF_PUCCH_Format2_value2enum_10,	/* "tag" => N; sorted by tag */
	asn_MAP_deltaF_PUCCH_Format2_enum2value_10,	/* N => "tag"; sorted by N */
	4,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_deltaF_PUCCH_Format2_tags_10[] = {
	(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_deltaF_PUCCH_Format2_10 = {
	"deltaF-PUCCH-Format2",
	"deltaF-PUCCH-Format2",
	&asn_OP_NativeEnumerated,
	asn_DEF_deltaF_PUCCH_Format2_tags_10,
	sizeof(asn_DEF_deltaF_PUCCH_Format2_tags_10)
		/sizeof(asn_DEF_deltaF_PUCCH_Format2_tags_10[0]) - 1, /* 1 */
	asn_DEF_deltaF_PUCCH_Format2_tags_10,	/* Same as above */
	sizeof(asn_DEF_deltaF_PUCCH_Format2_tags_10)
		/sizeof(asn_DEF_deltaF_PUCCH_Format2_tags_10[0]), /* 2 */
	{ &asn_OER_type_deltaF_PUCCH_Format2_constr_10, &asn_PER_type_deltaF_PUCCH_Format2_constr_10, NativeEnumerated_constraint },
	0, 0,	/* Defined elsewhere */
	&asn_SPC_deltaF_PUCCH_Format2_specs_10	/* Additional specs */
};

static const asn_INTEGER_enum_map_t asn_MAP_deltaF_PUCCH_Format2a_value2enum_15[] = {
	{ 0,	8,	"deltaF-2" },
	{ 1,	7,	"deltaF0" },
	{ 2,	7,	"deltaF2" }
};
static const unsigned int asn_MAP_deltaF_PUCCH_Format2a_enum2value_15[] = {
	0,	/* deltaF-2(0) */
	1,	/* deltaF0(1) */
	2	/* deltaF2(2) */
};
static const asn_INTEGER_specifics_t asn_SPC_deltaF_PUCCH_Format2a_specs_15 = {
	asn_MAP_deltaF_PUCCH_Format2a_value2enum_15,	/* "tag" => N; sorted by tag */
	asn_MAP_deltaF_PUCCH_Format2a_enum2value_15,	/* N => "tag"; sorted by N */
	3,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_deltaF_PUCCH_Format2a_tags_15[] = {
	(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_deltaF_PUCCH_Format2a_15 = {
	"deltaF-PUCCH-Format2a",
	"deltaF-PUCCH-Format2a",
	&asn_OP_NativeEnumerated,
	asn_DEF_deltaF_PUCCH_Format2a_tags_15,
	sizeof(asn_DEF_deltaF_PUCCH_Format2a_tags_15)
		/sizeof(asn_DEF_deltaF_PUCCH_Format2a_tags_15[0]) - 1, /* 1 */
	asn_DEF_deltaF_PUCCH_Format2a_tags_15,	/* Same as above */
	sizeof(asn_DEF_deltaF_PUCCH_Format2a_tags_15)
		/sizeof(asn_DEF_deltaF_PUCCH_Format2a_tags_15[0]), /* 2 */
	{ &asn_OER_type_deltaF_PUCCH_Format2a_constr_15, &asn_PER_type_deltaF_PUCCH_Format2a_constr_15, NativeEnumerated_constraint },
	0, 0,	/* Defined elsewhere */
	&asn_SPC_deltaF_PUCCH_Format2a_specs_15	/* Additional specs */
};

static const asn_INTEGER_enum_map_t asn_MAP_deltaF_PUCCH_Format2b_value2enum_19[] = {
	{ 0,	8,	"deltaF-2" },
	{ 1,	7,	"deltaF0" },
	{ 2,	7,	"deltaF2" }
};
static const unsigned int asn_MAP_deltaF_PUCCH_Format2b_enum2value_19[] = {
	0,	/* deltaF-2(0) */
	1,	/* deltaF0(1) */
	2	/* deltaF2(2) */
};
static const asn_INTEGER_specifics_t asn_SPC_deltaF_PUCCH_Format2b_specs_19 = {
	asn_MAP_deltaF_PUCCH_Format2b_value2enum_19,	/* "tag" => N; sorted by tag */
	asn_MAP_deltaF_PUCCH_Format2b_enum2value_19,	/* N => "tag"; sorted by N */
	3,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_deltaF_PUCCH_Format2b_tags_19[] = {
	(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_deltaF_PUCCH_Format2b_19 = {
	"deltaF-PUCCH-Format2b",
	"deltaF-PUCCH-Format2b",
	&asn_OP_NativeEnumerated,
	asn_DEF_deltaF_PUCCH_Format2b_tags_19,
	sizeof(asn_DEF_deltaF_PUCCH_Format2b_tags_19)
		/sizeof(asn_DEF_deltaF_PUCCH_Format2b_tags_19[0]) - 1, /* 1 */
	asn_DEF_deltaF_PUCCH_Format2b_tags_19,	/* Same as above */
	sizeof(asn_DEF_deltaF_PUCCH_Format2b_tags_19)
		/sizeof(asn_DEF_deltaF_PUCCH_Format2b_tags_19[0]), /* 2 */
	{ &asn_OER_type_deltaF_PUCCH_Format2b_constr_19, &asn_PER_type_deltaF_PUCCH_Format2b_constr_19, NativeEnumerated_constraint },
	0, 0,	/* Defined elsewhere */
	&asn_SPC_deltaF_PUCCH_Format2b_specs_19	/* Additional specs */
};

asn_TYPE_member_t asn_MBR_DeltaFList_PUCCH_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct DeltaFList_PUCCH, deltaF_PUCCH_Format1),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_deltaF_PUCCH_Format1_2,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"deltaF-PUCCH-Format1"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct DeltaFList_PUCCH, deltaF_PUCCH_Format1b),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_deltaF_PUCCH_Format1b_6,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"deltaF-PUCCH-Format1b"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct DeltaFList_PUCCH, deltaF_PUCCH_Format2),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_deltaF_PUCCH_Format2_10,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"deltaF-PUCCH-Format2"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct DeltaFList_PUCCH, deltaF_PUCCH_Format2a),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_deltaF_PUCCH_Format2a_15,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"deltaF-PUCCH-Format2a"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct DeltaFList_PUCCH, deltaF_PUCCH_Format2b),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_deltaF_PUCCH_Format2b_19,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"deltaF-PUCCH-Format2b"
		},
};
static const ber_tlv_tag_t asn_DEF_DeltaFList_PUCCH_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_DeltaFList_PUCCH_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* deltaF-PUCCH-Format1 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* deltaF-PUCCH-Format1b */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* deltaF-PUCCH-Format2 */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* deltaF-PUCCH-Format2a */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 } /* deltaF-PUCCH-Format2b */
};
asn_SEQUENCE_specifics_t asn_SPC_DeltaFList_PUCCH_specs_1 = {
	sizeof(struct DeltaFList_PUCCH),
	offsetof(struct DeltaFList_PUCCH, _asn_ctx),
	asn_MAP_DeltaFList_PUCCH_tag2el_1,
	5,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_DeltaFList_PUCCH = {
	"DeltaFList-PUCCH",
	"DeltaFList-PUCCH",
	&asn_OP_SEQUENCE,
	asn_DEF_DeltaFList_PUCCH_tags_1,
	sizeof(asn_DEF_DeltaFList_PUCCH_tags_1)
		/sizeof(asn_DEF_DeltaFList_PUCCH_tags_1[0]), /* 1 */
	asn_DEF_DeltaFList_PUCCH_tags_1,	/* Same as above */
	sizeof(asn_DEF_DeltaFList_PUCCH_tags_1)
		/sizeof(asn_DEF_DeltaFList_PUCCH_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_DeltaFList_PUCCH_1,
	5,	/* Elements count */
	&asn_SPC_DeltaFList_PUCCH_specs_1	/* Additional specs */
};

