/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "rrc.asn1"
 * 	`asn1c -fcompound-names -no-gen-example -gen-PER -pdu=RRCConnectionSetup -D src`
 */

#include "RLC-Config-v1530.h"

/*
 * This type is implemented using NativeEnumerated,
 * so here we adjust the DEF accordingly.
 */
static asn_oer_constraints_t asn_OER_type_rlc_OutOfOrderDelivery_r15_constr_4 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_rlc_OutOfOrderDelivery_r15_constr_4 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 0,  0,  0,  0 }	/* (0..0) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_type_RLC_Config_v1530_constr_1 CC_NOTUSED = {
	{ 0, 0 },
	-1};
asn_per_constraints_t asn_PER_type_RLC_Config_v1530_constr_1 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static const asn_INTEGER_enum_map_t asn_MAP_rlc_OutOfOrderDelivery_r15_value2enum_4[] = {
	{ 0,	4,	"true" }
};
static const unsigned int asn_MAP_rlc_OutOfOrderDelivery_r15_enum2value_4[] = {
	0	/* true(0) */
};
static const asn_INTEGER_specifics_t asn_SPC_rlc_OutOfOrderDelivery_r15_specs_4 = {
	asn_MAP_rlc_OutOfOrderDelivery_r15_value2enum_4,	/* "tag" => N; sorted by tag */
	asn_MAP_rlc_OutOfOrderDelivery_r15_enum2value_4,	/* N => "tag"; sorted by N */
	1,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_rlc_OutOfOrderDelivery_r15_tags_4[] = {
	(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_rlc_OutOfOrderDelivery_r15_4 = {
	"rlc-OutOfOrderDelivery-r15",
	"rlc-OutOfOrderDelivery-r15",
	&asn_OP_NativeEnumerated,
	asn_DEF_rlc_OutOfOrderDelivery_r15_tags_4,
	sizeof(asn_DEF_rlc_OutOfOrderDelivery_r15_tags_4)
		/sizeof(asn_DEF_rlc_OutOfOrderDelivery_r15_tags_4[0]) - 1, /* 1 */
	asn_DEF_rlc_OutOfOrderDelivery_r15_tags_4,	/* Same as above */
	sizeof(asn_DEF_rlc_OutOfOrderDelivery_r15_tags_4)
		/sizeof(asn_DEF_rlc_OutOfOrderDelivery_r15_tags_4[0]), /* 2 */
	{ &asn_OER_type_rlc_OutOfOrderDelivery_r15_constr_4, &asn_PER_type_rlc_OutOfOrderDelivery_r15_constr_4, NativeEnumerated_constraint },
	0, 0,	/* Defined elsewhere */
	&asn_SPC_rlc_OutOfOrderDelivery_r15_specs_4	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_setup_3[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct RLC_Config_v1530__setup, rlc_OutOfOrderDelivery_r15),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_rlc_OutOfOrderDelivery_r15_4,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"rlc-OutOfOrderDelivery-r15"
		},
};
static const ber_tlv_tag_t asn_DEF_setup_tags_3[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_setup_tag2el_3[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 } /* rlc-OutOfOrderDelivery-r15 */
};
static asn_SEQUENCE_specifics_t asn_SPC_setup_specs_3 = {
	sizeof(struct RLC_Config_v1530__setup),
	offsetof(struct RLC_Config_v1530__setup, _asn_ctx),
	asn_MAP_setup_tag2el_3,
	1,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_setup_3 = {
	"setup",
	"setup",
	&asn_OP_SEQUENCE,
	asn_DEF_setup_tags_3,
	sizeof(asn_DEF_setup_tags_3)
		/sizeof(asn_DEF_setup_tags_3[0]) - 1, /* 1 */
	asn_DEF_setup_tags_3,	/* Same as above */
	sizeof(asn_DEF_setup_tags_3)
		/sizeof(asn_DEF_setup_tags_3[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_setup_3,
	1,	/* Elements count */
	&asn_SPC_setup_specs_3	/* Additional specs */
};

asn_TYPE_member_t asn_MBR_RLC_Config_v1530_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct RLC_Config_v1530, choice.release),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"release"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct RLC_Config_v1530, choice.setup),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		0,
		&asn_DEF_setup_3,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"setup"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_RLC_Config_v1530_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* release */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* setup */
};
asn_CHOICE_specifics_t asn_SPC_RLC_Config_v1530_specs_1 = {
	sizeof(struct RLC_Config_v1530),
	offsetof(struct RLC_Config_v1530, _asn_ctx),
	offsetof(struct RLC_Config_v1530, present),
	sizeof(((struct RLC_Config_v1530 *)0)->present),
	asn_MAP_RLC_Config_v1530_tag2el_1,
	2,	/* Count of tags in the map */
	0, 0,
	-1	/* Extensions start */
};
asn_TYPE_descriptor_t asn_DEF_RLC_Config_v1530 = {
	"RLC-Config-v1530",
	"RLC-Config-v1530",
	&asn_OP_CHOICE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ &asn_OER_type_RLC_Config_v1530_constr_1, &asn_PER_type_RLC_Config_v1530_constr_1, CHOICE_constraint },
	asn_MBR_RLC_Config_v1530_1,
	2,	/* Elements count */
	&asn_SPC_RLC_Config_v1530_specs_1	/* Additional specs */
};

