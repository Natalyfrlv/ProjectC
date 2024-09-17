/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "rrc.asn1"
 * 	`asn1c -fcompound-names -no-gen-example -gen-PER -pdu=RRCConnectionSetup -D src`
 */

#include "TDD-ConfigSL-r12.h"

/*
 * This type is implemented using NativeEnumerated,
 * so here we adjust the DEF accordingly.
 */
static asn_oer_constraints_t asn_OER_type_subframeAssignmentSL_r12_constr_2 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_subframeAssignmentSL_r12_constr_2 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 3,  3,  0,  7 }	/* (0..7) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static const asn_INTEGER_enum_map_t asn_MAP_subframeAssignmentSL_r12_value2enum_2[] = {
	{ 0,	4,	"none" },
	{ 1,	3,	"sa0" },
	{ 2,	3,	"sa1" },
	{ 3,	3,	"sa2" },
	{ 4,	3,	"sa3" },
	{ 5,	3,	"sa4" },
	{ 6,	3,	"sa5" },
	{ 7,	3,	"sa6" }
};
static const unsigned int asn_MAP_subframeAssignmentSL_r12_enum2value_2[] = {
	0,	/* none(0) */
	1,	/* sa0(1) */
	2,	/* sa1(2) */
	3,	/* sa2(3) */
	4,	/* sa3(4) */
	5,	/* sa4(5) */
	6,	/* sa5(6) */
	7	/* sa6(7) */
};
static const asn_INTEGER_specifics_t asn_SPC_subframeAssignmentSL_r12_specs_2 = {
	asn_MAP_subframeAssignmentSL_r12_value2enum_2,	/* "tag" => N; sorted by tag */
	asn_MAP_subframeAssignmentSL_r12_enum2value_2,	/* N => "tag"; sorted by N */
	8,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_subframeAssignmentSL_r12_tags_2[] = {
	(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_subframeAssignmentSL_r12_2 = {
	"subframeAssignmentSL-r12",
	"subframeAssignmentSL-r12",
	&asn_OP_NativeEnumerated,
	asn_DEF_subframeAssignmentSL_r12_tags_2,
	sizeof(asn_DEF_subframeAssignmentSL_r12_tags_2)
		/sizeof(asn_DEF_subframeAssignmentSL_r12_tags_2[0]) - 1, /* 1 */
	asn_DEF_subframeAssignmentSL_r12_tags_2,	/* Same as above */
	sizeof(asn_DEF_subframeAssignmentSL_r12_tags_2)
		/sizeof(asn_DEF_subframeAssignmentSL_r12_tags_2[0]), /* 2 */
	{ &asn_OER_type_subframeAssignmentSL_r12_constr_2, &asn_PER_type_subframeAssignmentSL_r12_constr_2, NativeEnumerated_constraint },
	0, 0,	/* Defined elsewhere */
	&asn_SPC_subframeAssignmentSL_r12_specs_2	/* Additional specs */
};

asn_TYPE_member_t asn_MBR_TDD_ConfigSL_r12_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct TDD_ConfigSL_r12, subframeAssignmentSL_r12),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_subframeAssignmentSL_r12_2,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"subframeAssignmentSL-r12"
		},
};
static const ber_tlv_tag_t asn_DEF_TDD_ConfigSL_r12_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_TDD_ConfigSL_r12_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 } /* subframeAssignmentSL-r12 */
};
asn_SEQUENCE_specifics_t asn_SPC_TDD_ConfigSL_r12_specs_1 = {
	sizeof(struct TDD_ConfigSL_r12),
	offsetof(struct TDD_ConfigSL_r12, _asn_ctx),
	asn_MAP_TDD_ConfigSL_r12_tag2el_1,
	1,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_TDD_ConfigSL_r12 = {
	"TDD-ConfigSL-r12",
	"TDD-ConfigSL-r12",
	&asn_OP_SEQUENCE,
	asn_DEF_TDD_ConfigSL_r12_tags_1,
	sizeof(asn_DEF_TDD_ConfigSL_r12_tags_1)
		/sizeof(asn_DEF_TDD_ConfigSL_r12_tags_1[0]), /* 1 */
	asn_DEF_TDD_ConfigSL_r12_tags_1,	/* Same as above */
	sizeof(asn_DEF_TDD_ConfigSL_r12_tags_1)
		/sizeof(asn_DEF_TDD_ConfigSL_r12_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_TDD_ConfigSL_r12_1,
	1,	/* Elements count */
	&asn_SPC_TDD_ConfigSL_r12_specs_1	/* Additional specs */
};

