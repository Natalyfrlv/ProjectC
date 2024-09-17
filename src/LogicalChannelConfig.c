/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "rrc.asn1"
 * 	`asn1c -fcompound-names -no-gen-example -gen-PER -pdu=RRCConnectionSetup -D src`
 */

#include "LogicalChannelConfig.h"

/*
 * This type is implemented using NativeEnumerated,
 * so here we adjust the DEF accordingly.
 */
/*
 * This type is implemented using NativeEnumerated,
 * so here we adjust the DEF accordingly.
 */
static int
memb_priority_constraint_2(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= 1 && value <= 16)) {
		/* Constraint check succeeded */
		return 0;
	} else {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static int
memb_logicalChannelGroup_constraint_2(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= 0 && value <= 3)) {
		/* Constraint check succeeded */
		return 0;
	} else {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

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
static int
memb_setup_constraint_55(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= 1 && value <= 4)) {
		/* Constraint check succeeded */
		return 0;
	} else {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static int
memb_lch_CellRestriction_r15_constraint_1(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	const BIT_STRING_t *st = (const BIT_STRING_t *)sptr;
	size_t size;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	if(st->size > 0) {
		/* Size in bits */
		size = 8 * st->size - (st->bits_unused & 0x07);
	} else {
		size = 0;
	}
	
	if((size == 32)) {
		/* Constraint check succeeded */
		return 0;
	} else {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static asn_oer_constraints_t asn_OER_type_prioritisedBitRate_constr_4 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_prioritisedBitRate_constr_4 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 4,  4,  0,  15 }	/* (0..15) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_type_bucketSizeDuration_constr_21 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_bucketSizeDuration_constr_21 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 3,  3,  0,  7 }	/* (0..7) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_memb_priority_constr_3 CC_NOTUSED = {
	{ 1, 1 }	/* (1..16) */,
	-1};
static asn_per_constraints_t asn_PER_memb_priority_constr_3 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 4,  4,  1,  16 }	/* (1..16) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_memb_logicalChannelGroup_constr_30 CC_NOTUSED = {
	{ 1, 1 }	/* (0..3) */,
	-1};
static asn_per_constraints_t asn_PER_memb_logicalChannelGroup_constr_30 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 2,  2,  0,  3 }	/* (0..3) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_type_logicalChannelSR_Mask_r9_constr_32 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_logicalChannelSR_Mask_r9_constr_32 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 0,  0,  0,  0 }	/* (0..0) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_type_bitRateQueryProhibitTimer_r14_constr_36 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_bitRateQueryProhibitTimer_r14_constr_36 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 3,  3,  0,  7 }	/* (0..7) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_type_allowedTTI_Lengths_r15_constr_45 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_allowedTTI_Lengths_r15_constr_45 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_type_setup_constr_52 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_setup_constr_52 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_type_logicalChannelSR_Restriction_r15_constr_50 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_logicalChannelSR_Restriction_r15_constr_50 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_memb_setup_constr_57 CC_NOTUSED = {
	{ 1, 1 }	/* (1..4) */,
	-1};
static asn_per_constraints_t asn_PER_memb_setup_constr_57 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 2,  2,  1,  4 }	/* (1..4) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_type_channellAccessPriority_r15_constr_55 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_channellAccessPriority_r15_constr_55 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_memb_lch_CellRestriction_r15_constr_58 CC_NOTUSED = {
	{ 0, 0 },
	32	/* (SIZE(32..32)) */};
static asn_per_constraints_t asn_PER_memb_lch_CellRestriction_r15_constr_58 CC_NOTUSED = {
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	{ APC_CONSTRAINED,	 0,  0,  32,  32 }	/* (SIZE(32..32)) */,
	0, 0	/* No PER value map */
};
static const asn_INTEGER_enum_map_t asn_MAP_prioritisedBitRate_value2enum_4[] = {
	{ 0,	5,	"kBps0" },
	{ 1,	5,	"kBps8" },
	{ 2,	6,	"kBps16" },
	{ 3,	6,	"kBps32" },
	{ 4,	6,	"kBps64" },
	{ 5,	7,	"kBps128" },
	{ 6,	7,	"kBps256" },
	{ 7,	8,	"infinity" },
	{ 8,	13,	"kBps512-v1020" },
	{ 9,	14,	"kBps1024-v1020" },
	{ 10,	14,	"kBps2048-v1020" },
	{ 11,	6,	"spare5" },
	{ 12,	6,	"spare4" },
	{ 13,	6,	"spare3" },
	{ 14,	6,	"spare2" },
	{ 15,	6,	"spare1" }
};
static const unsigned int asn_MAP_prioritisedBitRate_enum2value_4[] = {
	7,	/* infinity(7) */
	0,	/* kBps0(0) */
	9,	/* kBps1024-v1020(9) */
	5,	/* kBps128(5) */
	2,	/* kBps16(2) */
	10,	/* kBps2048-v1020(10) */
	6,	/* kBps256(6) */
	3,	/* kBps32(3) */
	8,	/* kBps512-v1020(8) */
	4,	/* kBps64(4) */
	1,	/* kBps8(1) */
	15,	/* spare1(15) */
	14,	/* spare2(14) */
	13,	/* spare3(13) */
	12,	/* spare4(12) */
	11	/* spare5(11) */
};
static const asn_INTEGER_specifics_t asn_SPC_prioritisedBitRate_specs_4 = {
	asn_MAP_prioritisedBitRate_value2enum_4,	/* "tag" => N; sorted by tag */
	asn_MAP_prioritisedBitRate_enum2value_4,	/* N => "tag"; sorted by N */
	16,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_prioritisedBitRate_tags_4[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_prioritisedBitRate_4 = {
	"prioritisedBitRate",
	"prioritisedBitRate",
	&asn_OP_NativeEnumerated,
	asn_DEF_prioritisedBitRate_tags_4,
	sizeof(asn_DEF_prioritisedBitRate_tags_4)
		/sizeof(asn_DEF_prioritisedBitRate_tags_4[0]) - 1, /* 1 */
	asn_DEF_prioritisedBitRate_tags_4,	/* Same as above */
	sizeof(asn_DEF_prioritisedBitRate_tags_4)
		/sizeof(asn_DEF_prioritisedBitRate_tags_4[0]), /* 2 */
	{ &asn_OER_type_prioritisedBitRate_constr_4, &asn_PER_type_prioritisedBitRate_constr_4, NativeEnumerated_constraint },
	0, 0,	/* Defined elsewhere */
	&asn_SPC_prioritisedBitRate_specs_4	/* Additional specs */
};

static const asn_INTEGER_enum_map_t asn_MAP_bucketSizeDuration_value2enum_21[] = {
	{ 0,	4,	"ms50" },
	{ 1,	5,	"ms100" },
	{ 2,	5,	"ms150" },
	{ 3,	5,	"ms300" },
	{ 4,	5,	"ms500" },
	{ 5,	6,	"ms1000" },
	{ 6,	6,	"spare2" },
	{ 7,	6,	"spare1" }
};
static const unsigned int asn_MAP_bucketSizeDuration_enum2value_21[] = {
	1,	/* ms100(1) */
	5,	/* ms1000(5) */
	2,	/* ms150(2) */
	3,	/* ms300(3) */
	0,	/* ms50(0) */
	4,	/* ms500(4) */
	7,	/* spare1(7) */
	6	/* spare2(6) */
};
static const asn_INTEGER_specifics_t asn_SPC_bucketSizeDuration_specs_21 = {
	asn_MAP_bucketSizeDuration_value2enum_21,	/* "tag" => N; sorted by tag */
	asn_MAP_bucketSizeDuration_enum2value_21,	/* N => "tag"; sorted by N */
	8,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_bucketSizeDuration_tags_21[] = {
	(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_bucketSizeDuration_21 = {
	"bucketSizeDuration",
	"bucketSizeDuration",
	&asn_OP_NativeEnumerated,
	asn_DEF_bucketSizeDuration_tags_21,
	sizeof(asn_DEF_bucketSizeDuration_tags_21)
		/sizeof(asn_DEF_bucketSizeDuration_tags_21[0]) - 1, /* 1 */
	asn_DEF_bucketSizeDuration_tags_21,	/* Same as above */
	sizeof(asn_DEF_bucketSizeDuration_tags_21)
		/sizeof(asn_DEF_bucketSizeDuration_tags_21[0]), /* 2 */
	{ &asn_OER_type_bucketSizeDuration_constr_21, &asn_PER_type_bucketSizeDuration_constr_21, NativeEnumerated_constraint },
	0, 0,	/* Defined elsewhere */
	&asn_SPC_bucketSizeDuration_specs_21	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_ul_SpecificParameters_2[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct LogicalChannelConfig__ul_SpecificParameters, priority),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		0,
		{ &asn_OER_memb_priority_constr_3, &asn_PER_memb_priority_constr_3,  memb_priority_constraint_2 },
		0, 0, /* No default value */
		"priority"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct LogicalChannelConfig__ul_SpecificParameters, prioritisedBitRate),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_prioritisedBitRate_4,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"prioritisedBitRate"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct LogicalChannelConfig__ul_SpecificParameters, bucketSizeDuration),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_bucketSizeDuration_21,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"bucketSizeDuration"
		},
	{ ATF_POINTER, 1, offsetof(struct LogicalChannelConfig__ul_SpecificParameters, logicalChannelGroup),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		0,
		{ &asn_OER_memb_logicalChannelGroup_constr_30, &asn_PER_memb_logicalChannelGroup_constr_30,  memb_logicalChannelGroup_constraint_2 },
		0, 0, /* No default value */
		"logicalChannelGroup"
		},
};
static const int asn_MAP_ul_SpecificParameters_oms_2[] = { 3 };
static const ber_tlv_tag_t asn_DEF_ul_SpecificParameters_tags_2[] = {
	(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_ul_SpecificParameters_tag2el_2[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* priority */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* prioritisedBitRate */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* bucketSizeDuration */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 } /* logicalChannelGroup */
};
static asn_SEQUENCE_specifics_t asn_SPC_ul_SpecificParameters_specs_2 = {
	sizeof(struct LogicalChannelConfig__ul_SpecificParameters),
	offsetof(struct LogicalChannelConfig__ul_SpecificParameters, _asn_ctx),
	asn_MAP_ul_SpecificParameters_tag2el_2,
	4,	/* Count of tags in the map */
	asn_MAP_ul_SpecificParameters_oms_2,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_ul_SpecificParameters_2 = {
	"ul-SpecificParameters",
	"ul-SpecificParameters",
	&asn_OP_SEQUENCE,
	asn_DEF_ul_SpecificParameters_tags_2,
	sizeof(asn_DEF_ul_SpecificParameters_tags_2)
		/sizeof(asn_DEF_ul_SpecificParameters_tags_2[0]) - 1, /* 1 */
	asn_DEF_ul_SpecificParameters_tags_2,	/* Same as above */
	sizeof(asn_DEF_ul_SpecificParameters_tags_2)
		/sizeof(asn_DEF_ul_SpecificParameters_tags_2[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_ul_SpecificParameters_2,
	4,	/* Elements count */
	&asn_SPC_ul_SpecificParameters_specs_2	/* Additional specs */
};

static const asn_INTEGER_enum_map_t asn_MAP_logicalChannelSR_Mask_r9_value2enum_32[] = {
	{ 0,	5,	"setup" }
};
static const unsigned int asn_MAP_logicalChannelSR_Mask_r9_enum2value_32[] = {
	0	/* setup(0) */
};
static const asn_INTEGER_specifics_t asn_SPC_logicalChannelSR_Mask_r9_specs_32 = {
	asn_MAP_logicalChannelSR_Mask_r9_value2enum_32,	/* "tag" => N; sorted by tag */
	asn_MAP_logicalChannelSR_Mask_r9_enum2value_32,	/* N => "tag"; sorted by N */
	1,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_logicalChannelSR_Mask_r9_tags_32[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_logicalChannelSR_Mask_r9_32 = {
	"logicalChannelSR-Mask-r9",
	"logicalChannelSR-Mask-r9",
	&asn_OP_NativeEnumerated,
	asn_DEF_logicalChannelSR_Mask_r9_tags_32,
	sizeof(asn_DEF_logicalChannelSR_Mask_r9_tags_32)
		/sizeof(asn_DEF_logicalChannelSR_Mask_r9_tags_32[0]) - 1, /* 1 */
	asn_DEF_logicalChannelSR_Mask_r9_tags_32,	/* Same as above */
	sizeof(asn_DEF_logicalChannelSR_Mask_r9_tags_32)
		/sizeof(asn_DEF_logicalChannelSR_Mask_r9_tags_32[0]), /* 2 */
	{ &asn_OER_type_logicalChannelSR_Mask_r9_constr_32, &asn_PER_type_logicalChannelSR_Mask_r9_constr_32, NativeEnumerated_constraint },
	0, 0,	/* Defined elsewhere */
	&asn_SPC_logicalChannelSR_Mask_r9_specs_32	/* Additional specs */
};

static const asn_INTEGER_enum_map_t asn_MAP_bitRateQueryProhibitTimer_r14_value2enum_36[] = {
	{ 0,	2,	"s0" },
	{ 1,	6,	"s0dot4" },
	{ 2,	6,	"s0dot8" },
	{ 3,	6,	"s1dot6" },
	{ 4,	2,	"s3" },
	{ 5,	2,	"s6" },
	{ 6,	3,	"s12" },
	{ 7,	3,	"s30" }
};
static const unsigned int asn_MAP_bitRateQueryProhibitTimer_r14_enum2value_36[] = {
	0,	/* s0(0) */
	1,	/* s0dot4(1) */
	2,	/* s0dot8(2) */
	6,	/* s12(6) */
	3,	/* s1dot6(3) */
	4,	/* s3(4) */
	7,	/* s30(7) */
	5	/* s6(5) */
};
static const asn_INTEGER_specifics_t asn_SPC_bitRateQueryProhibitTimer_r14_specs_36 = {
	asn_MAP_bitRateQueryProhibitTimer_r14_value2enum_36,	/* "tag" => N; sorted by tag */
	asn_MAP_bitRateQueryProhibitTimer_r14_enum2value_36,	/* N => "tag"; sorted by N */
	8,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_bitRateQueryProhibitTimer_r14_tags_36[] = {
	(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_bitRateQueryProhibitTimer_r14_36 = {
	"bitRateQueryProhibitTimer-r14",
	"bitRateQueryProhibitTimer-r14",
	&asn_OP_NativeEnumerated,
	asn_DEF_bitRateQueryProhibitTimer_r14_tags_36,
	sizeof(asn_DEF_bitRateQueryProhibitTimer_r14_tags_36)
		/sizeof(asn_DEF_bitRateQueryProhibitTimer_r14_tags_36[0]) - 1, /* 1 */
	asn_DEF_bitRateQueryProhibitTimer_r14_tags_36,	/* Same as above */
	sizeof(asn_DEF_bitRateQueryProhibitTimer_r14_tags_36)
		/sizeof(asn_DEF_bitRateQueryProhibitTimer_r14_tags_36[0]), /* 2 */
	{ &asn_OER_type_bitRateQueryProhibitTimer_r14_constr_36, &asn_PER_type_bitRateQueryProhibitTimer_r14_constr_36, NativeEnumerated_constraint },
	0, 0,	/* Defined elsewhere */
	&asn_SPC_bitRateQueryProhibitTimer_r14_specs_36	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_setup_47[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct LogicalChannelConfig__allowedTTI_Lengths_r15__setup, shortTTI_r15),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_BOOLEAN,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"shortTTI-r15"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct LogicalChannelConfig__allowedTTI_Lengths_r15__setup, subframeTTI_r15),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_BOOLEAN,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"subframeTTI-r15"
		},
};
static const ber_tlv_tag_t asn_DEF_setup_tags_47[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_setup_tag2el_47[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* shortTTI-r15 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* subframeTTI-r15 */
};
static asn_SEQUENCE_specifics_t asn_SPC_setup_specs_47 = {
	sizeof(struct LogicalChannelConfig__allowedTTI_Lengths_r15__setup),
	offsetof(struct LogicalChannelConfig__allowedTTI_Lengths_r15__setup, _asn_ctx),
	asn_MAP_setup_tag2el_47,
	2,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_setup_47 = {
	"setup",
	"setup",
	&asn_OP_SEQUENCE,
	asn_DEF_setup_tags_47,
	sizeof(asn_DEF_setup_tags_47)
		/sizeof(asn_DEF_setup_tags_47[0]) - 1, /* 1 */
	asn_DEF_setup_tags_47,	/* Same as above */
	sizeof(asn_DEF_setup_tags_47)
		/sizeof(asn_DEF_setup_tags_47[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_setup_47,
	2,	/* Elements count */
	&asn_SPC_setup_specs_47	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_allowedTTI_Lengths_r15_45[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct LogicalChannelConfig__allowedTTI_Lengths_r15, choice.release),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"release"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct LogicalChannelConfig__allowedTTI_Lengths_r15, choice.setup),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		0,
		&asn_DEF_setup_47,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"setup"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_allowedTTI_Lengths_r15_tag2el_45[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* release */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* setup */
};
static asn_CHOICE_specifics_t asn_SPC_allowedTTI_Lengths_r15_specs_45 = {
	sizeof(struct LogicalChannelConfig__allowedTTI_Lengths_r15),
	offsetof(struct LogicalChannelConfig__allowedTTI_Lengths_r15, _asn_ctx),
	offsetof(struct LogicalChannelConfig__allowedTTI_Lengths_r15, present),
	sizeof(((struct LogicalChannelConfig__allowedTTI_Lengths_r15 *)0)->present),
	asn_MAP_allowedTTI_Lengths_r15_tag2el_45,
	2,	/* Count of tags in the map */
	0, 0,
	-1	/* Extensions start */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_allowedTTI_Lengths_r15_45 = {
	"allowedTTI-Lengths-r15",
	"allowedTTI-Lengths-r15",
	&asn_OP_CHOICE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ &asn_OER_type_allowedTTI_Lengths_r15_constr_45, &asn_PER_type_allowedTTI_Lengths_r15_constr_45, CHOICE_constraint },
	asn_MBR_allowedTTI_Lengths_r15_45,
	2,	/* Elements count */
	&asn_SPC_allowedTTI_Lengths_r15_specs_45	/* Additional specs */
};

static const asn_INTEGER_enum_map_t asn_MAP_setup_value2enum_52[] = {
	{ 0,	6,	"spucch" },
	{ 1,	5,	"pucch" }
};
static const unsigned int asn_MAP_setup_enum2value_52[] = {
	1,	/* pucch(1) */
	0	/* spucch(0) */
};
static const asn_INTEGER_specifics_t asn_SPC_setup_specs_52 = {
	asn_MAP_setup_value2enum_52,	/* "tag" => N; sorted by tag */
	asn_MAP_setup_enum2value_52,	/* N => "tag"; sorted by N */
	2,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_setup_tags_52[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_setup_52 = {
	"setup",
	"setup",
	&asn_OP_NativeEnumerated,
	asn_DEF_setup_tags_52,
	sizeof(asn_DEF_setup_tags_52)
		/sizeof(asn_DEF_setup_tags_52[0]) - 1, /* 1 */
	asn_DEF_setup_tags_52,	/* Same as above */
	sizeof(asn_DEF_setup_tags_52)
		/sizeof(asn_DEF_setup_tags_52[0]), /* 2 */
	{ &asn_OER_type_setup_constr_52, &asn_PER_type_setup_constr_52, NativeEnumerated_constraint },
	0, 0,	/* Defined elsewhere */
	&asn_SPC_setup_specs_52	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_logicalChannelSR_Restriction_r15_50[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct LogicalChannelConfig__logicalChannelSR_Restriction_r15, choice.release),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"release"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct LogicalChannelConfig__logicalChannelSR_Restriction_r15, choice.setup),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_setup_52,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"setup"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_logicalChannelSR_Restriction_r15_tag2el_50[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* release */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* setup */
};
static asn_CHOICE_specifics_t asn_SPC_logicalChannelSR_Restriction_r15_specs_50 = {
	sizeof(struct LogicalChannelConfig__logicalChannelSR_Restriction_r15),
	offsetof(struct LogicalChannelConfig__logicalChannelSR_Restriction_r15, _asn_ctx),
	offsetof(struct LogicalChannelConfig__logicalChannelSR_Restriction_r15, present),
	sizeof(((struct LogicalChannelConfig__logicalChannelSR_Restriction_r15 *)0)->present),
	asn_MAP_logicalChannelSR_Restriction_r15_tag2el_50,
	2,	/* Count of tags in the map */
	0, 0,
	-1	/* Extensions start */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_logicalChannelSR_Restriction_r15_50 = {
	"logicalChannelSR-Restriction-r15",
	"logicalChannelSR-Restriction-r15",
	&asn_OP_CHOICE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ &asn_OER_type_logicalChannelSR_Restriction_r15_constr_50, &asn_PER_type_logicalChannelSR_Restriction_r15_constr_50, CHOICE_constraint },
	asn_MBR_logicalChannelSR_Restriction_r15_50,
	2,	/* Elements count */
	&asn_SPC_logicalChannelSR_Restriction_r15_specs_50	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_channellAccessPriority_r15_55[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct LogicalChannelConfig__channellAccessPriority_r15, choice.release),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"release"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct LogicalChannelConfig__channellAccessPriority_r15, choice.setup),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		0,
		{ &asn_OER_memb_setup_constr_57, &asn_PER_memb_setup_constr_57,  memb_setup_constraint_55 },
		0, 0, /* No default value */
		"setup"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_channellAccessPriority_r15_tag2el_55[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* release */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* setup */
};
static asn_CHOICE_specifics_t asn_SPC_channellAccessPriority_r15_specs_55 = {
	sizeof(struct LogicalChannelConfig__channellAccessPriority_r15),
	offsetof(struct LogicalChannelConfig__channellAccessPriority_r15, _asn_ctx),
	offsetof(struct LogicalChannelConfig__channellAccessPriority_r15, present),
	sizeof(((struct LogicalChannelConfig__channellAccessPriority_r15 *)0)->present),
	asn_MAP_channellAccessPriority_r15_tag2el_55,
	2,	/* Count of tags in the map */
	0, 0,
	-1	/* Extensions start */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_channellAccessPriority_r15_55 = {
	"channellAccessPriority-r15",
	"channellAccessPriority-r15",
	&asn_OP_CHOICE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ &asn_OER_type_channellAccessPriority_r15_constr_55, &asn_PER_type_channellAccessPriority_r15_constr_55, CHOICE_constraint },
	asn_MBR_channellAccessPriority_r15_55,
	2,	/* Elements count */
	&asn_SPC_channellAccessPriority_r15_specs_55	/* Additional specs */
};

asn_TYPE_member_t asn_MBR_LogicalChannelConfig_1[] = {
	{ ATF_POINTER, 9, offsetof(struct LogicalChannelConfig, ul_SpecificParameters),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		0,
		&asn_DEF_ul_SpecificParameters_2,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"ul-SpecificParameters"
		},
	{ ATF_POINTER, 8, offsetof(struct LogicalChannelConfig, logicalChannelSR_Mask_r9),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_logicalChannelSR_Mask_r9_32,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"logicalChannelSR-Mask-r9"
		},
	{ ATF_POINTER, 7, offsetof(struct LogicalChannelConfig, logicalChannelSR_Prohibit_r12),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_BOOLEAN,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"logicalChannelSR-Prohibit-r12"
		},
	{ ATF_POINTER, 6, offsetof(struct LogicalChannelConfig, laa_UL_Allowed_r14),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_BOOLEAN,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"laa-UL-Allowed-r14"
		},
	{ ATF_POINTER, 5, offsetof(struct LogicalChannelConfig, bitRateQueryProhibitTimer_r14),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_bitRateQueryProhibitTimer_r14_36,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"bitRateQueryProhibitTimer-r14"
		},
	{ ATF_POINTER, 4, offsetof(struct LogicalChannelConfig, allowedTTI_Lengths_r15),
		(ASN_TAG_CLASS_CONTEXT | (5 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_allowedTTI_Lengths_r15_45,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"allowedTTI-Lengths-r15"
		},
	{ ATF_POINTER, 3, offsetof(struct LogicalChannelConfig, logicalChannelSR_Restriction_r15),
		(ASN_TAG_CLASS_CONTEXT | (6 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_logicalChannelSR_Restriction_r15_50,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"logicalChannelSR-Restriction-r15"
		},
	{ ATF_POINTER, 2, offsetof(struct LogicalChannelConfig, channellAccessPriority_r15),
		(ASN_TAG_CLASS_CONTEXT | (7 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_channellAccessPriority_r15_55,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"channellAccessPriority-r15"
		},
	{ ATF_POINTER, 1, offsetof(struct LogicalChannelConfig, lch_CellRestriction_r15),
		(ASN_TAG_CLASS_CONTEXT | (8 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_BIT_STRING,
		0,
		{ &asn_OER_memb_lch_CellRestriction_r15_constr_58, &asn_PER_memb_lch_CellRestriction_r15_constr_58,  memb_lch_CellRestriction_r15_constraint_1 },
		0, 0, /* No default value */
		"lch-CellRestriction-r15"
		},
};
static const int asn_MAP_LogicalChannelConfig_oms_1[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8 };
static const ber_tlv_tag_t asn_DEF_LogicalChannelConfig_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_LogicalChannelConfig_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* ul-SpecificParameters */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* logicalChannelSR-Mask-r9 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* logicalChannelSR-Prohibit-r12 */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* laa-UL-Allowed-r14 */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 }, /* bitRateQueryProhibitTimer-r14 */
    { (ASN_TAG_CLASS_CONTEXT | (5 << 2)), 5, 0, 0 }, /* allowedTTI-Lengths-r15 */
    { (ASN_TAG_CLASS_CONTEXT | (6 << 2)), 6, 0, 0 }, /* logicalChannelSR-Restriction-r15 */
    { (ASN_TAG_CLASS_CONTEXT | (7 << 2)), 7, 0, 0 }, /* channellAccessPriority-r15 */
    { (ASN_TAG_CLASS_CONTEXT | (8 << 2)), 8, 0, 0 } /* lch-CellRestriction-r15 */
};
asn_SEQUENCE_specifics_t asn_SPC_LogicalChannelConfig_specs_1 = {
	sizeof(struct LogicalChannelConfig),
	offsetof(struct LogicalChannelConfig, _asn_ctx),
	asn_MAP_LogicalChannelConfig_tag2el_1,
	9,	/* Count of tags in the map */
	asn_MAP_LogicalChannelConfig_oms_1,	/* Optional members */
	1, 8,	/* Root/Additions */
	1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_LogicalChannelConfig = {
	"LogicalChannelConfig",
	"LogicalChannelConfig",
	&asn_OP_SEQUENCE,
	asn_DEF_LogicalChannelConfig_tags_1,
	sizeof(asn_DEF_LogicalChannelConfig_tags_1)
		/sizeof(asn_DEF_LogicalChannelConfig_tags_1[0]), /* 1 */
	asn_DEF_LogicalChannelConfig_tags_1,	/* Same as above */
	sizeof(asn_DEF_LogicalChannelConfig_tags_1)
		/sizeof(asn_DEF_LogicalChannelConfig_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_LogicalChannelConfig_1,
	9,	/* Elements count */
	&asn_SPC_LogicalChannelConfig_specs_1	/* Additional specs */
};
