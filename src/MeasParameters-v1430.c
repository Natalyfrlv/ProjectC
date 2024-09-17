/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "rrc.asn1"
 * 	`asn1c -fcompound-names -no-gen-example -gen-PER -pdu=RRCConnectionSetup -D src`
 */

#include "MeasParameters-v1430.h"

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
static asn_oer_constraints_t asn_OER_type_ceMeasurements_r14_constr_2 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_ceMeasurements_r14_constr_2 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 0,  0,  0,  0 }	/* (0..0) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_type_ncsg_r14_constr_4 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_ncsg_r14_constr_4 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 0,  0,  0,  0 }	/* (0..0) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_type_shortMeasurementGap_r14_constr_6 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_shortMeasurementGap_r14_constr_6 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 0,  0,  0,  0 }	/* (0..0) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_type_perServingCellMeasurementGap_r14_constr_8 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_perServingCellMeasurementGap_r14_constr_8 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 0,  0,  0,  0 }	/* (0..0) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_type_nonUniformGap_r14_constr_10 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_nonUniformGap_r14_constr_10 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 0,  0,  0,  0 }	/* (0..0) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static const asn_INTEGER_enum_map_t asn_MAP_ceMeasurements_r14_value2enum_2[] = {
	{ 0,	9,	"supported" }
};
static const unsigned int asn_MAP_ceMeasurements_r14_enum2value_2[] = {
	0	/* supported(0) */
};
static const asn_INTEGER_specifics_t asn_SPC_ceMeasurements_r14_specs_2 = {
	asn_MAP_ceMeasurements_r14_value2enum_2,	/* "tag" => N; sorted by tag */
	asn_MAP_ceMeasurements_r14_enum2value_2,	/* N => "tag"; sorted by N */
	1,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_ceMeasurements_r14_tags_2[] = {
	(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_ceMeasurements_r14_2 = {
	"ceMeasurements-r14",
	"ceMeasurements-r14",
	&asn_OP_NativeEnumerated,
	asn_DEF_ceMeasurements_r14_tags_2,
	sizeof(asn_DEF_ceMeasurements_r14_tags_2)
		/sizeof(asn_DEF_ceMeasurements_r14_tags_2[0]) - 1, /* 1 */
	asn_DEF_ceMeasurements_r14_tags_2,	/* Same as above */
	sizeof(asn_DEF_ceMeasurements_r14_tags_2)
		/sizeof(asn_DEF_ceMeasurements_r14_tags_2[0]), /* 2 */
	{ &asn_OER_type_ceMeasurements_r14_constr_2, &asn_PER_type_ceMeasurements_r14_constr_2, NativeEnumerated_constraint },
	0, 0,	/* Defined elsewhere */
	&asn_SPC_ceMeasurements_r14_specs_2	/* Additional specs */
};

static const asn_INTEGER_enum_map_t asn_MAP_ncsg_r14_value2enum_4[] = {
	{ 0,	9,	"supported" }
};
static const unsigned int asn_MAP_ncsg_r14_enum2value_4[] = {
	0	/* supported(0) */
};
static const asn_INTEGER_specifics_t asn_SPC_ncsg_r14_specs_4 = {
	asn_MAP_ncsg_r14_value2enum_4,	/* "tag" => N; sorted by tag */
	asn_MAP_ncsg_r14_enum2value_4,	/* N => "tag"; sorted by N */
	1,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_ncsg_r14_tags_4[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_ncsg_r14_4 = {
	"ncsg-r14",
	"ncsg-r14",
	&asn_OP_NativeEnumerated,
	asn_DEF_ncsg_r14_tags_4,
	sizeof(asn_DEF_ncsg_r14_tags_4)
		/sizeof(asn_DEF_ncsg_r14_tags_4[0]) - 1, /* 1 */
	asn_DEF_ncsg_r14_tags_4,	/* Same as above */
	sizeof(asn_DEF_ncsg_r14_tags_4)
		/sizeof(asn_DEF_ncsg_r14_tags_4[0]), /* 2 */
	{ &asn_OER_type_ncsg_r14_constr_4, &asn_PER_type_ncsg_r14_constr_4, NativeEnumerated_constraint },
	0, 0,	/* Defined elsewhere */
	&asn_SPC_ncsg_r14_specs_4	/* Additional specs */
};

static const asn_INTEGER_enum_map_t asn_MAP_shortMeasurementGap_r14_value2enum_6[] = {
	{ 0,	9,	"supported" }
};
static const unsigned int asn_MAP_shortMeasurementGap_r14_enum2value_6[] = {
	0	/* supported(0) */
};
static const asn_INTEGER_specifics_t asn_SPC_shortMeasurementGap_r14_specs_6 = {
	asn_MAP_shortMeasurementGap_r14_value2enum_6,	/* "tag" => N; sorted by tag */
	asn_MAP_shortMeasurementGap_r14_enum2value_6,	/* N => "tag"; sorted by N */
	1,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_shortMeasurementGap_r14_tags_6[] = {
	(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_shortMeasurementGap_r14_6 = {
	"shortMeasurementGap-r14",
	"shortMeasurementGap-r14",
	&asn_OP_NativeEnumerated,
	asn_DEF_shortMeasurementGap_r14_tags_6,
	sizeof(asn_DEF_shortMeasurementGap_r14_tags_6)
		/sizeof(asn_DEF_shortMeasurementGap_r14_tags_6[0]) - 1, /* 1 */
	asn_DEF_shortMeasurementGap_r14_tags_6,	/* Same as above */
	sizeof(asn_DEF_shortMeasurementGap_r14_tags_6)
		/sizeof(asn_DEF_shortMeasurementGap_r14_tags_6[0]), /* 2 */
	{ &asn_OER_type_shortMeasurementGap_r14_constr_6, &asn_PER_type_shortMeasurementGap_r14_constr_6, NativeEnumerated_constraint },
	0, 0,	/* Defined elsewhere */
	&asn_SPC_shortMeasurementGap_r14_specs_6	/* Additional specs */
};

static const asn_INTEGER_enum_map_t asn_MAP_perServingCellMeasurementGap_r14_value2enum_8[] = {
	{ 0,	9,	"supported" }
};
static const unsigned int asn_MAP_perServingCellMeasurementGap_r14_enum2value_8[] = {
	0	/* supported(0) */
};
static const asn_INTEGER_specifics_t asn_SPC_perServingCellMeasurementGap_r14_specs_8 = {
	asn_MAP_perServingCellMeasurementGap_r14_value2enum_8,	/* "tag" => N; sorted by tag */
	asn_MAP_perServingCellMeasurementGap_r14_enum2value_8,	/* N => "tag"; sorted by N */
	1,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_perServingCellMeasurementGap_r14_tags_8[] = {
	(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_perServingCellMeasurementGap_r14_8 = {
	"perServingCellMeasurementGap-r14",
	"perServingCellMeasurementGap-r14",
	&asn_OP_NativeEnumerated,
	asn_DEF_perServingCellMeasurementGap_r14_tags_8,
	sizeof(asn_DEF_perServingCellMeasurementGap_r14_tags_8)
		/sizeof(asn_DEF_perServingCellMeasurementGap_r14_tags_8[0]) - 1, /* 1 */
	asn_DEF_perServingCellMeasurementGap_r14_tags_8,	/* Same as above */
	sizeof(asn_DEF_perServingCellMeasurementGap_r14_tags_8)
		/sizeof(asn_DEF_perServingCellMeasurementGap_r14_tags_8[0]), /* 2 */
	{ &asn_OER_type_perServingCellMeasurementGap_r14_constr_8, &asn_PER_type_perServingCellMeasurementGap_r14_constr_8, NativeEnumerated_constraint },
	0, 0,	/* Defined elsewhere */
	&asn_SPC_perServingCellMeasurementGap_r14_specs_8	/* Additional specs */
};

static const asn_INTEGER_enum_map_t asn_MAP_nonUniformGap_r14_value2enum_10[] = {
	{ 0,	9,	"supported" }
};
static const unsigned int asn_MAP_nonUniformGap_r14_enum2value_10[] = {
	0	/* supported(0) */
};
static const asn_INTEGER_specifics_t asn_SPC_nonUniformGap_r14_specs_10 = {
	asn_MAP_nonUniformGap_r14_value2enum_10,	/* "tag" => N; sorted by tag */
	asn_MAP_nonUniformGap_r14_enum2value_10,	/* N => "tag"; sorted by N */
	1,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_nonUniformGap_r14_tags_10[] = {
	(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_nonUniformGap_r14_10 = {
	"nonUniformGap-r14",
	"nonUniformGap-r14",
	&asn_OP_NativeEnumerated,
	asn_DEF_nonUniformGap_r14_tags_10,
	sizeof(asn_DEF_nonUniformGap_r14_tags_10)
		/sizeof(asn_DEF_nonUniformGap_r14_tags_10[0]) - 1, /* 1 */
	asn_DEF_nonUniformGap_r14_tags_10,	/* Same as above */
	sizeof(asn_DEF_nonUniformGap_r14_tags_10)
		/sizeof(asn_DEF_nonUniformGap_r14_tags_10[0]), /* 2 */
	{ &asn_OER_type_nonUniformGap_r14_constr_10, &asn_PER_type_nonUniformGap_r14_constr_10, NativeEnumerated_constraint },
	0, 0,	/* Defined elsewhere */
	&asn_SPC_nonUniformGap_r14_specs_10	/* Additional specs */
};

asn_TYPE_member_t asn_MBR_MeasParameters_v1430_1[] = {
	{ ATF_POINTER, 5, offsetof(struct MeasParameters_v1430, ceMeasurements_r14),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_ceMeasurements_r14_2,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"ceMeasurements-r14"
		},
	{ ATF_POINTER, 4, offsetof(struct MeasParameters_v1430, ncsg_r14),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_ncsg_r14_4,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"ncsg-r14"
		},
	{ ATF_POINTER, 3, offsetof(struct MeasParameters_v1430, shortMeasurementGap_r14),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_shortMeasurementGap_r14_6,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"shortMeasurementGap-r14"
		},
	{ ATF_POINTER, 2, offsetof(struct MeasParameters_v1430, perServingCellMeasurementGap_r14),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_perServingCellMeasurementGap_r14_8,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"perServingCellMeasurementGap-r14"
		},
	{ ATF_POINTER, 1, offsetof(struct MeasParameters_v1430, nonUniformGap_r14),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_nonUniformGap_r14_10,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"nonUniformGap-r14"
		},
};
static const int asn_MAP_MeasParameters_v1430_oms_1[] = { 0, 1, 2, 3, 4 };
static const ber_tlv_tag_t asn_DEF_MeasParameters_v1430_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_MeasParameters_v1430_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* ceMeasurements-r14 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* ncsg-r14 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* shortMeasurementGap-r14 */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* perServingCellMeasurementGap-r14 */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 } /* nonUniformGap-r14 */
};
asn_SEQUENCE_specifics_t asn_SPC_MeasParameters_v1430_specs_1 = {
	sizeof(struct MeasParameters_v1430),
	offsetof(struct MeasParameters_v1430, _asn_ctx),
	asn_MAP_MeasParameters_v1430_tag2el_1,
	5,	/* Count of tags in the map */
	asn_MAP_MeasParameters_v1430_oms_1,	/* Optional members */
	5, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_MeasParameters_v1430 = {
	"MeasParameters-v1430",
	"MeasParameters-v1430",
	&asn_OP_SEQUENCE,
	asn_DEF_MeasParameters_v1430_tags_1,
	sizeof(asn_DEF_MeasParameters_v1430_tags_1)
		/sizeof(asn_DEF_MeasParameters_v1430_tags_1[0]), /* 1 */
	asn_DEF_MeasParameters_v1430_tags_1,	/* Same as above */
	sizeof(asn_DEF_MeasParameters_v1430_tags_1)
		/sizeof(asn_DEF_MeasParameters_v1430_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_MeasParameters_v1430_1,
	5,	/* Elements count */
	&asn_SPC_MeasParameters_v1430_specs_1	/* Additional specs */
};

