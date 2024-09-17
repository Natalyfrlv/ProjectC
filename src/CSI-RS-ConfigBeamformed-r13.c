/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "rrc.asn1"
 * 	`asn1c -fcompound-names -no-gen-example -gen-PER -pdu=RRCConnectionSetup -D src`
 */

#include "CSI-RS-ConfigBeamformed-r13.h"

/*
 * This type is implemented using NativeEnumerated,
 * so here we adjust the DEF accordingly.
 */
/*
 * This type is implemented using NativeEnumerated,
 * so here we adjust the DEF accordingly.
 */
static int
memb_csi_RS_ConfigNZPIdListExt_r13_constraint_1(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	size_t size;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	/* Determine the number of elements */
	size = _A_CSEQUENCE_FROM_VOID(sptr)->count;
	
	if((size >= 1 && size <= 7)) {
		/* Perform validation of the inner elements */
		return SEQUENCE_OF_constraint(td, sptr, ctfailcb, app_key);
	} else {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static int
memb_csi_IM_ConfigIdList_r13_constraint_1(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	size_t size;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	/* Determine the number of elements */
	size = _A_CSEQUENCE_FROM_VOID(sptr)->count;
	
	if((size >= 1 && size <= 8)) {
		/* Perform validation of the inner elements */
		return SEQUENCE_OF_constraint(td, sptr, ctfailcb, app_key);
	} else {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static int
memb_p_C_AndCBSR_PerResourceConfigList_r13_constraint_1(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	size_t size;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	/* Determine the number of elements */
	size = _A_CSEQUENCE_FROM_VOID(sptr)->count;
	
	if((size >= 1 && size <= 8)) {
		/* Perform validation of the inner elements */
		return SEQUENCE_OF_constraint(td, sptr, ctfailcb, app_key);
	} else {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static int
memb_ace_For4Tx_PerResourceConfigList_r13_constraint_1(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	size_t size;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	/* Determine the number of elements */
	size = _A_CSEQUENCE_FROM_VOID(sptr)->count;
	
	if((size >= 1 && size <= 7)) {
		/* Perform validation of the inner elements */
		return SEQUENCE_OF_constraint(td, sptr, ctfailcb, app_key);
	} else {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static asn_oer_constraints_t asn_OER_type_csi_RS_ConfigNZPIdListExt_r13_constr_2 CC_NOTUSED = {
	{ 0, 0 },
	-1	/* (SIZE(1..7)) */};
static asn_per_constraints_t asn_PER_type_csi_RS_ConfigNZPIdListExt_r13_constr_2 CC_NOTUSED = {
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	{ APC_CONSTRAINED,	 3,  3,  1,  7 }	/* (SIZE(1..7)) */,
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_type_csi_IM_ConfigIdList_r13_constr_4 CC_NOTUSED = {
	{ 0, 0 },
	-1	/* (SIZE(1..8)) */};
static asn_per_constraints_t asn_PER_type_csi_IM_ConfigIdList_r13_constr_4 CC_NOTUSED = {
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	{ APC_CONSTRAINED,	 3,  3,  1,  8 }	/* (SIZE(1..8)) */,
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_type_p_C_AndCBSR_PerResourceConfigList_r13_constr_6 CC_NOTUSED = {
	{ 0, 0 },
	-1	/* (SIZE(1..8)) */};
static asn_per_constraints_t asn_PER_type_p_C_AndCBSR_PerResourceConfigList_r13_constr_6 CC_NOTUSED = {
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	{ APC_CONSTRAINED,	 3,  3,  1,  8 }	/* (SIZE(1..8)) */,
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_type_ace_For4Tx_PerResourceConfigList_r13_constr_8 CC_NOTUSED = {
	{ 0, 0 },
	-1	/* (SIZE(1..7)) */};
static asn_per_constraints_t asn_PER_type_ace_For4Tx_PerResourceConfigList_r13_constr_8 CC_NOTUSED = {
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	{ APC_CONSTRAINED,	 3,  3,  1,  7 }	/* (SIZE(1..7)) */,
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_type_alternativeCodebookEnabledBeamformed_r13_constr_10 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_alternativeCodebookEnabledBeamformed_r13_constr_10 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 0,  0,  0,  0 }	/* (0..0) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_type_channelMeasRestriction_r13_constr_12 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_channelMeasRestriction_r13_constr_12 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 0,  0,  0,  0 }	/* (0..0) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_memb_csi_RS_ConfigNZPIdListExt_r13_constr_2 CC_NOTUSED = {
	{ 0, 0 },
	-1	/* (SIZE(1..7)) */};
static asn_per_constraints_t asn_PER_memb_csi_RS_ConfigNZPIdListExt_r13_constr_2 CC_NOTUSED = {
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	{ APC_CONSTRAINED,	 3,  3,  1,  7 }	/* (SIZE(1..7)) */,
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_memb_csi_IM_ConfigIdList_r13_constr_4 CC_NOTUSED = {
	{ 0, 0 },
	-1	/* (SIZE(1..8)) */};
static asn_per_constraints_t asn_PER_memb_csi_IM_ConfigIdList_r13_constr_4 CC_NOTUSED = {
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	{ APC_CONSTRAINED,	 3,  3,  1,  8 }	/* (SIZE(1..8)) */,
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_memb_p_C_AndCBSR_PerResourceConfigList_r13_constr_6 CC_NOTUSED = {
	{ 0, 0 },
	-1	/* (SIZE(1..8)) */};
static asn_per_constraints_t asn_PER_memb_p_C_AndCBSR_PerResourceConfigList_r13_constr_6 CC_NOTUSED = {
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	{ APC_CONSTRAINED,	 3,  3,  1,  8 }	/* (SIZE(1..8)) */,
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_memb_ace_For4Tx_PerResourceConfigList_r13_constr_8 CC_NOTUSED = {
	{ 0, 0 },
	-1	/* (SIZE(1..7)) */};
static asn_per_constraints_t asn_PER_memb_ace_For4Tx_PerResourceConfigList_r13_constr_8 CC_NOTUSED = {
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	{ APC_CONSTRAINED,	 3,  3,  1,  7 }	/* (SIZE(1..7)) */,
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_csi_RS_ConfigNZPIdListExt_r13_2[] = {
	{ ATF_POINTER, 0, 0,
		(ASN_TAG_CLASS_UNIVERSAL | (2 << 2)),
		0,
		&asn_DEF_CSI_RS_ConfigNZPId_r13,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		""
		},
};
static const ber_tlv_tag_t asn_DEF_csi_RS_ConfigNZPIdListExt_r13_tags_2[] = {
	(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_SET_OF_specifics_t asn_SPC_csi_RS_ConfigNZPIdListExt_r13_specs_2 = {
	sizeof(struct CSI_RS_ConfigBeamformed_r13__csi_RS_ConfigNZPIdListExt_r13),
	offsetof(struct CSI_RS_ConfigBeamformed_r13__csi_RS_ConfigNZPIdListExt_r13, _asn_ctx),
	0,	/* XER encoding is XMLDelimitedItemList */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_csi_RS_ConfigNZPIdListExt_r13_2 = {
	"csi-RS-ConfigNZPIdListExt-r13",
	"csi-RS-ConfigNZPIdListExt-r13",
	&asn_OP_SEQUENCE_OF,
	asn_DEF_csi_RS_ConfigNZPIdListExt_r13_tags_2,
	sizeof(asn_DEF_csi_RS_ConfigNZPIdListExt_r13_tags_2)
		/sizeof(asn_DEF_csi_RS_ConfigNZPIdListExt_r13_tags_2[0]) - 1, /* 1 */
	asn_DEF_csi_RS_ConfigNZPIdListExt_r13_tags_2,	/* Same as above */
	sizeof(asn_DEF_csi_RS_ConfigNZPIdListExt_r13_tags_2)
		/sizeof(asn_DEF_csi_RS_ConfigNZPIdListExt_r13_tags_2[0]), /* 2 */
	{ &asn_OER_type_csi_RS_ConfigNZPIdListExt_r13_constr_2, &asn_PER_type_csi_RS_ConfigNZPIdListExt_r13_constr_2, SEQUENCE_OF_constraint },
	asn_MBR_csi_RS_ConfigNZPIdListExt_r13_2,
	1,	/* Single element */
	&asn_SPC_csi_RS_ConfigNZPIdListExt_r13_specs_2	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_csi_IM_ConfigIdList_r13_4[] = {
	{ ATF_POINTER, 0, 0,
		(ASN_TAG_CLASS_UNIVERSAL | (2 << 2)),
		0,
		&asn_DEF_CSI_IM_ConfigId_r13,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		""
		},
};
static const ber_tlv_tag_t asn_DEF_csi_IM_ConfigIdList_r13_tags_4[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_SET_OF_specifics_t asn_SPC_csi_IM_ConfigIdList_r13_specs_4 = {
	sizeof(struct CSI_RS_ConfigBeamformed_r13__csi_IM_ConfigIdList_r13),
	offsetof(struct CSI_RS_ConfigBeamformed_r13__csi_IM_ConfigIdList_r13, _asn_ctx),
	0,	/* XER encoding is XMLDelimitedItemList */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_csi_IM_ConfigIdList_r13_4 = {
	"csi-IM-ConfigIdList-r13",
	"csi-IM-ConfigIdList-r13",
	&asn_OP_SEQUENCE_OF,
	asn_DEF_csi_IM_ConfigIdList_r13_tags_4,
	sizeof(asn_DEF_csi_IM_ConfigIdList_r13_tags_4)
		/sizeof(asn_DEF_csi_IM_ConfigIdList_r13_tags_4[0]) - 1, /* 1 */
	asn_DEF_csi_IM_ConfigIdList_r13_tags_4,	/* Same as above */
	sizeof(asn_DEF_csi_IM_ConfigIdList_r13_tags_4)
		/sizeof(asn_DEF_csi_IM_ConfigIdList_r13_tags_4[0]), /* 2 */
	{ &asn_OER_type_csi_IM_ConfigIdList_r13_constr_4, &asn_PER_type_csi_IM_ConfigIdList_r13_constr_4, SEQUENCE_OF_constraint },
	asn_MBR_csi_IM_ConfigIdList_r13_4,
	1,	/* Single element */
	&asn_SPC_csi_IM_ConfigIdList_r13_specs_4	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_p_C_AndCBSR_PerResourceConfigList_r13_6[] = {
	{ ATF_POINTER, 0, 0,
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_P_C_AndCBSR_Pair_r13,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		""
		},
};
static const ber_tlv_tag_t asn_DEF_p_C_AndCBSR_PerResourceConfigList_r13_tags_6[] = {
	(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_SET_OF_specifics_t asn_SPC_p_C_AndCBSR_PerResourceConfigList_r13_specs_6 = {
	sizeof(struct CSI_RS_ConfigBeamformed_r13__p_C_AndCBSR_PerResourceConfigList_r13),
	offsetof(struct CSI_RS_ConfigBeamformed_r13__p_C_AndCBSR_PerResourceConfigList_r13, _asn_ctx),
	0,	/* XER encoding is XMLDelimitedItemList */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_p_C_AndCBSR_PerResourceConfigList_r13_6 = {
	"p-C-AndCBSR-PerResourceConfigList-r13",
	"p-C-AndCBSR-PerResourceConfigList-r13",
	&asn_OP_SEQUENCE_OF,
	asn_DEF_p_C_AndCBSR_PerResourceConfigList_r13_tags_6,
	sizeof(asn_DEF_p_C_AndCBSR_PerResourceConfigList_r13_tags_6)
		/sizeof(asn_DEF_p_C_AndCBSR_PerResourceConfigList_r13_tags_6[0]) - 1, /* 1 */
	asn_DEF_p_C_AndCBSR_PerResourceConfigList_r13_tags_6,	/* Same as above */
	sizeof(asn_DEF_p_C_AndCBSR_PerResourceConfigList_r13_tags_6)
		/sizeof(asn_DEF_p_C_AndCBSR_PerResourceConfigList_r13_tags_6[0]), /* 2 */
	{ &asn_OER_type_p_C_AndCBSR_PerResourceConfigList_r13_constr_6, &asn_PER_type_p_C_AndCBSR_PerResourceConfigList_r13_constr_6, SEQUENCE_OF_constraint },
	asn_MBR_p_C_AndCBSR_PerResourceConfigList_r13_6,
	1,	/* Single element */
	&asn_SPC_p_C_AndCBSR_PerResourceConfigList_r13_specs_6	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_ace_For4Tx_PerResourceConfigList_r13_8[] = {
	{ ATF_POINTER, 0, 0,
		(ASN_TAG_CLASS_UNIVERSAL | (1 << 2)),
		0,
		&asn_DEF_BOOLEAN,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		""
		},
};
static const ber_tlv_tag_t asn_DEF_ace_For4Tx_PerResourceConfigList_r13_tags_8[] = {
	(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_SET_OF_specifics_t asn_SPC_ace_For4Tx_PerResourceConfigList_r13_specs_8 = {
	sizeof(struct CSI_RS_ConfigBeamformed_r13__ace_For4Tx_PerResourceConfigList_r13),
	offsetof(struct CSI_RS_ConfigBeamformed_r13__ace_For4Tx_PerResourceConfigList_r13, _asn_ctx),
	1,	/* XER encoding is XMLValueList */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_ace_For4Tx_PerResourceConfigList_r13_8 = {
	"ace-For4Tx-PerResourceConfigList-r13",
	"ace-For4Tx-PerResourceConfigList-r13",
	&asn_OP_SEQUENCE_OF,
	asn_DEF_ace_For4Tx_PerResourceConfigList_r13_tags_8,
	sizeof(asn_DEF_ace_For4Tx_PerResourceConfigList_r13_tags_8)
		/sizeof(asn_DEF_ace_For4Tx_PerResourceConfigList_r13_tags_8[0]) - 1, /* 1 */
	asn_DEF_ace_For4Tx_PerResourceConfigList_r13_tags_8,	/* Same as above */
	sizeof(asn_DEF_ace_For4Tx_PerResourceConfigList_r13_tags_8)
		/sizeof(asn_DEF_ace_For4Tx_PerResourceConfigList_r13_tags_8[0]), /* 2 */
	{ &asn_OER_type_ace_For4Tx_PerResourceConfigList_r13_constr_8, &asn_PER_type_ace_For4Tx_PerResourceConfigList_r13_constr_8, SEQUENCE_OF_constraint },
	asn_MBR_ace_For4Tx_PerResourceConfigList_r13_8,
	1,	/* Single element */
	&asn_SPC_ace_For4Tx_PerResourceConfigList_r13_specs_8	/* Additional specs */
};

static const asn_INTEGER_enum_map_t asn_MAP_alternativeCodebookEnabledBeamformed_r13_value2enum_10[] = {
	{ 0,	4,	"true" }
};
static const unsigned int asn_MAP_alternativeCodebookEnabledBeamformed_r13_enum2value_10[] = {
	0	/* true(0) */
};
static const asn_INTEGER_specifics_t asn_SPC_alternativeCodebookEnabledBeamformed_r13_specs_10 = {
	asn_MAP_alternativeCodebookEnabledBeamformed_r13_value2enum_10,	/* "tag" => N; sorted by tag */
	asn_MAP_alternativeCodebookEnabledBeamformed_r13_enum2value_10,	/* N => "tag"; sorted by N */
	1,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_alternativeCodebookEnabledBeamformed_r13_tags_10[] = {
	(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_alternativeCodebookEnabledBeamformed_r13_10 = {
	"alternativeCodebookEnabledBeamformed-r13",
	"alternativeCodebookEnabledBeamformed-r13",
	&asn_OP_NativeEnumerated,
	asn_DEF_alternativeCodebookEnabledBeamformed_r13_tags_10,
	sizeof(asn_DEF_alternativeCodebookEnabledBeamformed_r13_tags_10)
		/sizeof(asn_DEF_alternativeCodebookEnabledBeamformed_r13_tags_10[0]) - 1, /* 1 */
	asn_DEF_alternativeCodebookEnabledBeamformed_r13_tags_10,	/* Same as above */
	sizeof(asn_DEF_alternativeCodebookEnabledBeamformed_r13_tags_10)
		/sizeof(asn_DEF_alternativeCodebookEnabledBeamformed_r13_tags_10[0]), /* 2 */
	{ &asn_OER_type_alternativeCodebookEnabledBeamformed_r13_constr_10, &asn_PER_type_alternativeCodebookEnabledBeamformed_r13_constr_10, NativeEnumerated_constraint },
	0, 0,	/* Defined elsewhere */
	&asn_SPC_alternativeCodebookEnabledBeamformed_r13_specs_10	/* Additional specs */
};

static const asn_INTEGER_enum_map_t asn_MAP_channelMeasRestriction_r13_value2enum_12[] = {
	{ 0,	2,	"on" }
};
static const unsigned int asn_MAP_channelMeasRestriction_r13_enum2value_12[] = {
	0	/* on(0) */
};
static const asn_INTEGER_specifics_t asn_SPC_channelMeasRestriction_r13_specs_12 = {
	asn_MAP_channelMeasRestriction_r13_value2enum_12,	/* "tag" => N; sorted by tag */
	asn_MAP_channelMeasRestriction_r13_enum2value_12,	/* N => "tag"; sorted by N */
	1,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_channelMeasRestriction_r13_tags_12[] = {
	(ASN_TAG_CLASS_CONTEXT | (5 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_channelMeasRestriction_r13_12 = {
	"channelMeasRestriction-r13",
	"channelMeasRestriction-r13",
	&asn_OP_NativeEnumerated,
	asn_DEF_channelMeasRestriction_r13_tags_12,
	sizeof(asn_DEF_channelMeasRestriction_r13_tags_12)
		/sizeof(asn_DEF_channelMeasRestriction_r13_tags_12[0]) - 1, /* 1 */
	asn_DEF_channelMeasRestriction_r13_tags_12,	/* Same as above */
	sizeof(asn_DEF_channelMeasRestriction_r13_tags_12)
		/sizeof(asn_DEF_channelMeasRestriction_r13_tags_12[0]), /* 2 */
	{ &asn_OER_type_channelMeasRestriction_r13_constr_12, &asn_PER_type_channelMeasRestriction_r13_constr_12, NativeEnumerated_constraint },
	0, 0,	/* Defined elsewhere */
	&asn_SPC_channelMeasRestriction_r13_specs_12	/* Additional specs */
};

asn_TYPE_member_t asn_MBR_CSI_RS_ConfigBeamformed_r13_1[] = {
	{ ATF_POINTER, 6, offsetof(struct CSI_RS_ConfigBeamformed_r13, csi_RS_ConfigNZPIdListExt_r13),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		0,
		&asn_DEF_csi_RS_ConfigNZPIdListExt_r13_2,
		0,
		{ &asn_OER_memb_csi_RS_ConfigNZPIdListExt_r13_constr_2, &asn_PER_memb_csi_RS_ConfigNZPIdListExt_r13_constr_2,  memb_csi_RS_ConfigNZPIdListExt_r13_constraint_1 },
		0, 0, /* No default value */
		"csi-RS-ConfigNZPIdListExt-r13"
		},
	{ ATF_POINTER, 5, offsetof(struct CSI_RS_ConfigBeamformed_r13, csi_IM_ConfigIdList_r13),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		0,
		&asn_DEF_csi_IM_ConfigIdList_r13_4,
		0,
		{ &asn_OER_memb_csi_IM_ConfigIdList_r13_constr_4, &asn_PER_memb_csi_IM_ConfigIdList_r13_constr_4,  memb_csi_IM_ConfigIdList_r13_constraint_1 },
		0, 0, /* No default value */
		"csi-IM-ConfigIdList-r13"
		},
	{ ATF_POINTER, 4, offsetof(struct CSI_RS_ConfigBeamformed_r13, p_C_AndCBSR_PerResourceConfigList_r13),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		0,
		&asn_DEF_p_C_AndCBSR_PerResourceConfigList_r13_6,
		0,
		{ &asn_OER_memb_p_C_AndCBSR_PerResourceConfigList_r13_constr_6, &asn_PER_memb_p_C_AndCBSR_PerResourceConfigList_r13_constr_6,  memb_p_C_AndCBSR_PerResourceConfigList_r13_constraint_1 },
		0, 0, /* No default value */
		"p-C-AndCBSR-PerResourceConfigList-r13"
		},
	{ ATF_POINTER, 3, offsetof(struct CSI_RS_ConfigBeamformed_r13, ace_For4Tx_PerResourceConfigList_r13),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		0,
		&asn_DEF_ace_For4Tx_PerResourceConfigList_r13_8,
		0,
		{ &asn_OER_memb_ace_For4Tx_PerResourceConfigList_r13_constr_8, &asn_PER_memb_ace_For4Tx_PerResourceConfigList_r13_constr_8,  memb_ace_For4Tx_PerResourceConfigList_r13_constraint_1 },
		0, 0, /* No default value */
		"ace-For4Tx-PerResourceConfigList-r13"
		},
	{ ATF_POINTER, 2, offsetof(struct CSI_RS_ConfigBeamformed_r13, alternativeCodebookEnabledBeamformed_r13),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_alternativeCodebookEnabledBeamformed_r13_10,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"alternativeCodebookEnabledBeamformed-r13"
		},
	{ ATF_POINTER, 1, offsetof(struct CSI_RS_ConfigBeamformed_r13, channelMeasRestriction_r13),
		(ASN_TAG_CLASS_CONTEXT | (5 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_channelMeasRestriction_r13_12,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"channelMeasRestriction-r13"
		},
};
static const int asn_MAP_CSI_RS_ConfigBeamformed_r13_oms_1[] = { 0, 1, 2, 3, 4, 5 };
static const ber_tlv_tag_t asn_DEF_CSI_RS_ConfigBeamformed_r13_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_CSI_RS_ConfigBeamformed_r13_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* csi-RS-ConfigNZPIdListExt-r13 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* csi-IM-ConfigIdList-r13 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* p-C-AndCBSR-PerResourceConfigList-r13 */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* ace-For4Tx-PerResourceConfigList-r13 */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 }, /* alternativeCodebookEnabledBeamformed-r13 */
    { (ASN_TAG_CLASS_CONTEXT | (5 << 2)), 5, 0, 0 } /* channelMeasRestriction-r13 */
};
asn_SEQUENCE_specifics_t asn_SPC_CSI_RS_ConfigBeamformed_r13_specs_1 = {
	sizeof(struct CSI_RS_ConfigBeamformed_r13),
	offsetof(struct CSI_RS_ConfigBeamformed_r13, _asn_ctx),
	asn_MAP_CSI_RS_ConfigBeamformed_r13_tag2el_1,
	6,	/* Count of tags in the map */
	asn_MAP_CSI_RS_ConfigBeamformed_r13_oms_1,	/* Optional members */
	6, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_CSI_RS_ConfigBeamformed_r13 = {
	"CSI-RS-ConfigBeamformed-r13",
	"CSI-RS-ConfigBeamformed-r13",
	&asn_OP_SEQUENCE,
	asn_DEF_CSI_RS_ConfigBeamformed_r13_tags_1,
	sizeof(asn_DEF_CSI_RS_ConfigBeamformed_r13_tags_1)
		/sizeof(asn_DEF_CSI_RS_ConfigBeamformed_r13_tags_1[0]), /* 1 */
	asn_DEF_CSI_RS_ConfigBeamformed_r13_tags_1,	/* Same as above */
	sizeof(asn_DEF_CSI_RS_ConfigBeamformed_r13_tags_1)
		/sizeof(asn_DEF_CSI_RS_ConfigBeamformed_r13_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_CSI_RS_ConfigBeamformed_r13_1,
	6,	/* Elements count */
	&asn_SPC_CSI_RS_ConfigBeamformed_r13_specs_1	/* Additional specs */
};

