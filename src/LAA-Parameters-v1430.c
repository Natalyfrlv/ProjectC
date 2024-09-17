/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "rrc.asn1"
 * 	`asn1c -fcompound-names -no-gen-example -gen-PER -pdu=RRCConnectionSetup -D src`
 */

#include "LAA-Parameters-v1430.h"

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
/*
 * This type is implemented using NativeEnumerated,
 * so here we adjust the DEF accordingly.
 */
static asn_oer_constraints_t asn_OER_type_crossCarrierSchedulingLAA_UL_r14_constr_2 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_crossCarrierSchedulingLAA_UL_r14_constr_2 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 0,  0,  0,  0 }	/* (0..0) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_type_uplinkLAA_r14_constr_4 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_uplinkLAA_r14_constr_4 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 0,  0,  0,  0 }	/* (0..0) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_type_twoStepSchedulingTimingInfo_r14_constr_6 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_twoStepSchedulingTimingInfo_r14_constr_6 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 2,  2,  0,  2 }	/* (0..2) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_type_uss_BlindDecodingAdjustment_r14_constr_10 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_uss_BlindDecodingAdjustment_r14_constr_10 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 0,  0,  0,  0 }	/* (0..0) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_type_uss_BlindDecodingReduction_r14_constr_12 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_uss_BlindDecodingReduction_r14_constr_12 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 0,  0,  0,  0 }	/* (0..0) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_type_outOfSequenceGrantHandling_r14_constr_14 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_outOfSequenceGrantHandling_r14_constr_14 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 0,  0,  0,  0 }	/* (0..0) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static const asn_INTEGER_enum_map_t asn_MAP_crossCarrierSchedulingLAA_UL_r14_value2enum_2[] = {
	{ 0,	9,	"supported" }
};
static const unsigned int asn_MAP_crossCarrierSchedulingLAA_UL_r14_enum2value_2[] = {
	0	/* supported(0) */
};
static const asn_INTEGER_specifics_t asn_SPC_crossCarrierSchedulingLAA_UL_r14_specs_2 = {
	asn_MAP_crossCarrierSchedulingLAA_UL_r14_value2enum_2,	/* "tag" => N; sorted by tag */
	asn_MAP_crossCarrierSchedulingLAA_UL_r14_enum2value_2,	/* N => "tag"; sorted by N */
	1,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_crossCarrierSchedulingLAA_UL_r14_tags_2[] = {
	(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_crossCarrierSchedulingLAA_UL_r14_2 = {
	"crossCarrierSchedulingLAA-UL-r14",
	"crossCarrierSchedulingLAA-UL-r14",
	&asn_OP_NativeEnumerated,
	asn_DEF_crossCarrierSchedulingLAA_UL_r14_tags_2,
	sizeof(asn_DEF_crossCarrierSchedulingLAA_UL_r14_tags_2)
		/sizeof(asn_DEF_crossCarrierSchedulingLAA_UL_r14_tags_2[0]) - 1, /* 1 */
	asn_DEF_crossCarrierSchedulingLAA_UL_r14_tags_2,	/* Same as above */
	sizeof(asn_DEF_crossCarrierSchedulingLAA_UL_r14_tags_2)
		/sizeof(asn_DEF_crossCarrierSchedulingLAA_UL_r14_tags_2[0]), /* 2 */
	{ &asn_OER_type_crossCarrierSchedulingLAA_UL_r14_constr_2, &asn_PER_type_crossCarrierSchedulingLAA_UL_r14_constr_2, NativeEnumerated_constraint },
	0, 0,	/* Defined elsewhere */
	&asn_SPC_crossCarrierSchedulingLAA_UL_r14_specs_2	/* Additional specs */
};

static const asn_INTEGER_enum_map_t asn_MAP_uplinkLAA_r14_value2enum_4[] = {
	{ 0,	9,	"supported" }
};
static const unsigned int asn_MAP_uplinkLAA_r14_enum2value_4[] = {
	0	/* supported(0) */
};
static const asn_INTEGER_specifics_t asn_SPC_uplinkLAA_r14_specs_4 = {
	asn_MAP_uplinkLAA_r14_value2enum_4,	/* "tag" => N; sorted by tag */
	asn_MAP_uplinkLAA_r14_enum2value_4,	/* N => "tag"; sorted by N */
	1,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_uplinkLAA_r14_tags_4[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_uplinkLAA_r14_4 = {
	"uplinkLAA-r14",
	"uplinkLAA-r14",
	&asn_OP_NativeEnumerated,
	asn_DEF_uplinkLAA_r14_tags_4,
	sizeof(asn_DEF_uplinkLAA_r14_tags_4)
		/sizeof(asn_DEF_uplinkLAA_r14_tags_4[0]) - 1, /* 1 */
	asn_DEF_uplinkLAA_r14_tags_4,	/* Same as above */
	sizeof(asn_DEF_uplinkLAA_r14_tags_4)
		/sizeof(asn_DEF_uplinkLAA_r14_tags_4[0]), /* 2 */
	{ &asn_OER_type_uplinkLAA_r14_constr_4, &asn_PER_type_uplinkLAA_r14_constr_4, NativeEnumerated_constraint },
	0, 0,	/* Defined elsewhere */
	&asn_SPC_uplinkLAA_r14_specs_4	/* Additional specs */
};

static const asn_INTEGER_enum_map_t asn_MAP_twoStepSchedulingTimingInfo_r14_value2enum_6[] = {
	{ 0,	6,	"nPlus1" },
	{ 1,	6,	"nPlus2" },
	{ 2,	6,	"nPlus3" }
};
static const unsigned int asn_MAP_twoStepSchedulingTimingInfo_r14_enum2value_6[] = {
	0,	/* nPlus1(0) */
	1,	/* nPlus2(1) */
	2	/* nPlus3(2) */
};
static const asn_INTEGER_specifics_t asn_SPC_twoStepSchedulingTimingInfo_r14_specs_6 = {
	asn_MAP_twoStepSchedulingTimingInfo_r14_value2enum_6,	/* "tag" => N; sorted by tag */
	asn_MAP_twoStepSchedulingTimingInfo_r14_enum2value_6,	/* N => "tag"; sorted by N */
	3,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_twoStepSchedulingTimingInfo_r14_tags_6[] = {
	(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_twoStepSchedulingTimingInfo_r14_6 = {
	"twoStepSchedulingTimingInfo-r14",
	"twoStepSchedulingTimingInfo-r14",
	&asn_OP_NativeEnumerated,
	asn_DEF_twoStepSchedulingTimingInfo_r14_tags_6,
	sizeof(asn_DEF_twoStepSchedulingTimingInfo_r14_tags_6)
		/sizeof(asn_DEF_twoStepSchedulingTimingInfo_r14_tags_6[0]) - 1, /* 1 */
	asn_DEF_twoStepSchedulingTimingInfo_r14_tags_6,	/* Same as above */
	sizeof(asn_DEF_twoStepSchedulingTimingInfo_r14_tags_6)
		/sizeof(asn_DEF_twoStepSchedulingTimingInfo_r14_tags_6[0]), /* 2 */
	{ &asn_OER_type_twoStepSchedulingTimingInfo_r14_constr_6, &asn_PER_type_twoStepSchedulingTimingInfo_r14_constr_6, NativeEnumerated_constraint },
	0, 0,	/* Defined elsewhere */
	&asn_SPC_twoStepSchedulingTimingInfo_r14_specs_6	/* Additional specs */
};

static const asn_INTEGER_enum_map_t asn_MAP_uss_BlindDecodingAdjustment_r14_value2enum_10[] = {
	{ 0,	9,	"supported" }
};
static const unsigned int asn_MAP_uss_BlindDecodingAdjustment_r14_enum2value_10[] = {
	0	/* supported(0) */
};
static const asn_INTEGER_specifics_t asn_SPC_uss_BlindDecodingAdjustment_r14_specs_10 = {
	asn_MAP_uss_BlindDecodingAdjustment_r14_value2enum_10,	/* "tag" => N; sorted by tag */
	asn_MAP_uss_BlindDecodingAdjustment_r14_enum2value_10,	/* N => "tag"; sorted by N */
	1,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_uss_BlindDecodingAdjustment_r14_tags_10[] = {
	(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_uss_BlindDecodingAdjustment_r14_10 = {
	"uss-BlindDecodingAdjustment-r14",
	"uss-BlindDecodingAdjustment-r14",
	&asn_OP_NativeEnumerated,
	asn_DEF_uss_BlindDecodingAdjustment_r14_tags_10,
	sizeof(asn_DEF_uss_BlindDecodingAdjustment_r14_tags_10)
		/sizeof(asn_DEF_uss_BlindDecodingAdjustment_r14_tags_10[0]) - 1, /* 1 */
	asn_DEF_uss_BlindDecodingAdjustment_r14_tags_10,	/* Same as above */
	sizeof(asn_DEF_uss_BlindDecodingAdjustment_r14_tags_10)
		/sizeof(asn_DEF_uss_BlindDecodingAdjustment_r14_tags_10[0]), /* 2 */
	{ &asn_OER_type_uss_BlindDecodingAdjustment_r14_constr_10, &asn_PER_type_uss_BlindDecodingAdjustment_r14_constr_10, NativeEnumerated_constraint },
	0, 0,	/* Defined elsewhere */
	&asn_SPC_uss_BlindDecodingAdjustment_r14_specs_10	/* Additional specs */
};

static const asn_INTEGER_enum_map_t asn_MAP_uss_BlindDecodingReduction_r14_value2enum_12[] = {
	{ 0,	9,	"supported" }
};
static const unsigned int asn_MAP_uss_BlindDecodingReduction_r14_enum2value_12[] = {
	0	/* supported(0) */
};
static const asn_INTEGER_specifics_t asn_SPC_uss_BlindDecodingReduction_r14_specs_12 = {
	asn_MAP_uss_BlindDecodingReduction_r14_value2enum_12,	/* "tag" => N; sorted by tag */
	asn_MAP_uss_BlindDecodingReduction_r14_enum2value_12,	/* N => "tag"; sorted by N */
	1,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_uss_BlindDecodingReduction_r14_tags_12[] = {
	(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_uss_BlindDecodingReduction_r14_12 = {
	"uss-BlindDecodingReduction-r14",
	"uss-BlindDecodingReduction-r14",
	&asn_OP_NativeEnumerated,
	asn_DEF_uss_BlindDecodingReduction_r14_tags_12,
	sizeof(asn_DEF_uss_BlindDecodingReduction_r14_tags_12)
		/sizeof(asn_DEF_uss_BlindDecodingReduction_r14_tags_12[0]) - 1, /* 1 */
	asn_DEF_uss_BlindDecodingReduction_r14_tags_12,	/* Same as above */
	sizeof(asn_DEF_uss_BlindDecodingReduction_r14_tags_12)
		/sizeof(asn_DEF_uss_BlindDecodingReduction_r14_tags_12[0]), /* 2 */
	{ &asn_OER_type_uss_BlindDecodingReduction_r14_constr_12, &asn_PER_type_uss_BlindDecodingReduction_r14_constr_12, NativeEnumerated_constraint },
	0, 0,	/* Defined elsewhere */
	&asn_SPC_uss_BlindDecodingReduction_r14_specs_12	/* Additional specs */
};

static const asn_INTEGER_enum_map_t asn_MAP_outOfSequenceGrantHandling_r14_value2enum_14[] = {
	{ 0,	9,	"supported" }
};
static const unsigned int asn_MAP_outOfSequenceGrantHandling_r14_enum2value_14[] = {
	0	/* supported(0) */
};
static const asn_INTEGER_specifics_t asn_SPC_outOfSequenceGrantHandling_r14_specs_14 = {
	asn_MAP_outOfSequenceGrantHandling_r14_value2enum_14,	/* "tag" => N; sorted by tag */
	asn_MAP_outOfSequenceGrantHandling_r14_enum2value_14,	/* N => "tag"; sorted by N */
	1,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_outOfSequenceGrantHandling_r14_tags_14[] = {
	(ASN_TAG_CLASS_CONTEXT | (5 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_outOfSequenceGrantHandling_r14_14 = {
	"outOfSequenceGrantHandling-r14",
	"outOfSequenceGrantHandling-r14",
	&asn_OP_NativeEnumerated,
	asn_DEF_outOfSequenceGrantHandling_r14_tags_14,
	sizeof(asn_DEF_outOfSequenceGrantHandling_r14_tags_14)
		/sizeof(asn_DEF_outOfSequenceGrantHandling_r14_tags_14[0]) - 1, /* 1 */
	asn_DEF_outOfSequenceGrantHandling_r14_tags_14,	/* Same as above */
	sizeof(asn_DEF_outOfSequenceGrantHandling_r14_tags_14)
		/sizeof(asn_DEF_outOfSequenceGrantHandling_r14_tags_14[0]), /* 2 */
	{ &asn_OER_type_outOfSequenceGrantHandling_r14_constr_14, &asn_PER_type_outOfSequenceGrantHandling_r14_constr_14, NativeEnumerated_constraint },
	0, 0,	/* Defined elsewhere */
	&asn_SPC_outOfSequenceGrantHandling_r14_specs_14	/* Additional specs */
};

asn_TYPE_member_t asn_MBR_LAA_Parameters_v1430_1[] = {
	{ ATF_POINTER, 6, offsetof(struct LAA_Parameters_v1430, crossCarrierSchedulingLAA_UL_r14),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_crossCarrierSchedulingLAA_UL_r14_2,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"crossCarrierSchedulingLAA-UL-r14"
		},
	{ ATF_POINTER, 5, offsetof(struct LAA_Parameters_v1430, uplinkLAA_r14),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_uplinkLAA_r14_4,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"uplinkLAA-r14"
		},
	{ ATF_POINTER, 4, offsetof(struct LAA_Parameters_v1430, twoStepSchedulingTimingInfo_r14),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_twoStepSchedulingTimingInfo_r14_6,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"twoStepSchedulingTimingInfo-r14"
		},
	{ ATF_POINTER, 3, offsetof(struct LAA_Parameters_v1430, uss_BlindDecodingAdjustment_r14),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_uss_BlindDecodingAdjustment_r14_10,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"uss-BlindDecodingAdjustment-r14"
		},
	{ ATF_POINTER, 2, offsetof(struct LAA_Parameters_v1430, uss_BlindDecodingReduction_r14),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_uss_BlindDecodingReduction_r14_12,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"uss-BlindDecodingReduction-r14"
		},
	{ ATF_POINTER, 1, offsetof(struct LAA_Parameters_v1430, outOfSequenceGrantHandling_r14),
		(ASN_TAG_CLASS_CONTEXT | (5 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_outOfSequenceGrantHandling_r14_14,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"outOfSequenceGrantHandling-r14"
		},
};
static const int asn_MAP_LAA_Parameters_v1430_oms_1[] = { 0, 1, 2, 3, 4, 5 };
static const ber_tlv_tag_t asn_DEF_LAA_Parameters_v1430_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_LAA_Parameters_v1430_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* crossCarrierSchedulingLAA-UL-r14 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* uplinkLAA-r14 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* twoStepSchedulingTimingInfo-r14 */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* uss-BlindDecodingAdjustment-r14 */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 }, /* uss-BlindDecodingReduction-r14 */
    { (ASN_TAG_CLASS_CONTEXT | (5 << 2)), 5, 0, 0 } /* outOfSequenceGrantHandling-r14 */
};
asn_SEQUENCE_specifics_t asn_SPC_LAA_Parameters_v1430_specs_1 = {
	sizeof(struct LAA_Parameters_v1430),
	offsetof(struct LAA_Parameters_v1430, _asn_ctx),
	asn_MAP_LAA_Parameters_v1430_tag2el_1,
	6,	/* Count of tags in the map */
	asn_MAP_LAA_Parameters_v1430_oms_1,	/* Optional members */
	6, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_LAA_Parameters_v1430 = {
	"LAA-Parameters-v1430",
	"LAA-Parameters-v1430",
	&asn_OP_SEQUENCE,
	asn_DEF_LAA_Parameters_v1430_tags_1,
	sizeof(asn_DEF_LAA_Parameters_v1430_tags_1)
		/sizeof(asn_DEF_LAA_Parameters_v1430_tags_1[0]), /* 1 */
	asn_DEF_LAA_Parameters_v1430_tags_1,	/* Same as above */
	sizeof(asn_DEF_LAA_Parameters_v1430_tags_1)
		/sizeof(asn_DEF_LAA_Parameters_v1430_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_LAA_Parameters_v1430_1,
	6,	/* Elements count */
	&asn_SPC_LAA_Parameters_v1430_specs_1	/* Additional specs */
};

