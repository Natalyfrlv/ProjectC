/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "rrc.asn1"
 * 	`asn1c -fcompound-names -no-gen-example -gen-PER -pdu=RRCConnectionSetup -D src`
 */

#include "SystemInformationBlockType1-v1430-IEs.h"

/*
 * This type is implemented using NativeEnumerated,
 * so here we adjust the DEF accordingly.
 */
static int
memb_cellAccessRelatedInfoList_r14_constraint_1(const asn_TYPE_descriptor_t *td, const void *sptr,
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
	
	if((size >= 1 && size <= 5)) {
		/* Perform validation of the inner elements */
		return SEQUENCE_OF_constraint(td, sptr, ctfailcb, app_key);
	} else {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static asn_oer_constraints_t asn_OER_type_eCallOverIMS_Support_r14_constr_2 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_eCallOverIMS_Support_r14_constr_2 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 0,  0,  0,  0 }	/* (0..0) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_type_cellAccessRelatedInfoList_r14_constr_5 CC_NOTUSED = {
	{ 0, 0 },
	-1	/* (SIZE(1..5)) */};
static asn_per_constraints_t asn_PER_type_cellAccessRelatedInfoList_r14_constr_5 CC_NOTUSED = {
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	{ APC_CONSTRAINED,	 3,  3,  1,  5 }	/* (SIZE(1..5)) */,
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_memb_cellAccessRelatedInfoList_r14_constr_5 CC_NOTUSED = {
	{ 0, 0 },
	-1	/* (SIZE(1..5)) */};
static asn_per_constraints_t asn_PER_memb_cellAccessRelatedInfoList_r14_constr_5 CC_NOTUSED = {
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	{ APC_CONSTRAINED,	 3,  3,  1,  5 }	/* (SIZE(1..5)) */,
	0, 0	/* No PER value map */
};
static const asn_INTEGER_enum_map_t asn_MAP_eCallOverIMS_Support_r14_value2enum_2[] = {
	{ 0,	4,	"true" }
};
static const unsigned int asn_MAP_eCallOverIMS_Support_r14_enum2value_2[] = {
	0	/* true(0) */
};
static const asn_INTEGER_specifics_t asn_SPC_eCallOverIMS_Support_r14_specs_2 = {
	asn_MAP_eCallOverIMS_Support_r14_value2enum_2,	/* "tag" => N; sorted by tag */
	asn_MAP_eCallOverIMS_Support_r14_enum2value_2,	/* N => "tag"; sorted by N */
	1,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_eCallOverIMS_Support_r14_tags_2[] = {
	(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_eCallOverIMS_Support_r14_2 = {
	"eCallOverIMS-Support-r14",
	"eCallOverIMS-Support-r14",
	&asn_OP_NativeEnumerated,
	asn_DEF_eCallOverIMS_Support_r14_tags_2,
	sizeof(asn_DEF_eCallOverIMS_Support_r14_tags_2)
		/sizeof(asn_DEF_eCallOverIMS_Support_r14_tags_2[0]) - 1, /* 1 */
	asn_DEF_eCallOverIMS_Support_r14_tags_2,	/* Same as above */
	sizeof(asn_DEF_eCallOverIMS_Support_r14_tags_2)
		/sizeof(asn_DEF_eCallOverIMS_Support_r14_tags_2[0]), /* 2 */
	{ &asn_OER_type_eCallOverIMS_Support_r14_constr_2, &asn_PER_type_eCallOverIMS_Support_r14_constr_2, NativeEnumerated_constraint },
	0, 0,	/* Defined elsewhere */
	&asn_SPC_eCallOverIMS_Support_r14_specs_2	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_cellAccessRelatedInfoList_r14_5[] = {
	{ ATF_POINTER, 0, 0,
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_CellAccessRelatedInfo_r14,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		""
		},
};
static const ber_tlv_tag_t asn_DEF_cellAccessRelatedInfoList_r14_tags_5[] = {
	(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_SET_OF_specifics_t asn_SPC_cellAccessRelatedInfoList_r14_specs_5 = {
	sizeof(struct SystemInformationBlockType1_v1430_IEs__cellAccessRelatedInfoList_r14),
	offsetof(struct SystemInformationBlockType1_v1430_IEs__cellAccessRelatedInfoList_r14, _asn_ctx),
	0,	/* XER encoding is XMLDelimitedItemList */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_cellAccessRelatedInfoList_r14_5 = {
	"cellAccessRelatedInfoList-r14",
	"cellAccessRelatedInfoList-r14",
	&asn_OP_SEQUENCE_OF,
	asn_DEF_cellAccessRelatedInfoList_r14_tags_5,
	sizeof(asn_DEF_cellAccessRelatedInfoList_r14_tags_5)
		/sizeof(asn_DEF_cellAccessRelatedInfoList_r14_tags_5[0]) - 1, /* 1 */
	asn_DEF_cellAccessRelatedInfoList_r14_tags_5,	/* Same as above */
	sizeof(asn_DEF_cellAccessRelatedInfoList_r14_tags_5)
		/sizeof(asn_DEF_cellAccessRelatedInfoList_r14_tags_5[0]), /* 2 */
	{ &asn_OER_type_cellAccessRelatedInfoList_r14_constr_5, &asn_PER_type_cellAccessRelatedInfoList_r14_constr_5, SEQUENCE_OF_constraint },
	asn_MBR_cellAccessRelatedInfoList_r14_5,
	1,	/* Single element */
	&asn_SPC_cellAccessRelatedInfoList_r14_specs_5	/* Additional specs */
};

asn_TYPE_member_t asn_MBR_SystemInformationBlockType1_v1430_IEs_1[] = {
	{ ATF_POINTER, 4, offsetof(struct SystemInformationBlockType1_v1430_IEs, eCallOverIMS_Support_r14),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_eCallOverIMS_Support_r14_2,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"eCallOverIMS-Support-r14"
		},
	{ ATF_POINTER, 3, offsetof(struct SystemInformationBlockType1_v1430_IEs, tdd_Config_v1430),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_TDD_Config_v1430,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"tdd-Config-v1430"
		},
	{ ATF_POINTER, 2, offsetof(struct SystemInformationBlockType1_v1430_IEs, cellAccessRelatedInfoList_r14),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		0,
		&asn_DEF_cellAccessRelatedInfoList_r14_5,
		0,
		{ &asn_OER_memb_cellAccessRelatedInfoList_r14_constr_5, &asn_PER_memb_cellAccessRelatedInfoList_r14_constr_5,  memb_cellAccessRelatedInfoList_r14_constraint_1 },
		0, 0, /* No default value */
		"cellAccessRelatedInfoList-r14"
		},
	{ ATF_POINTER, 1, offsetof(struct SystemInformationBlockType1_v1430_IEs, nonCriticalExtension),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_SystemInformationBlockType1_v1450_IEs,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"nonCriticalExtension"
		},
};
static const int asn_MAP_SystemInformationBlockType1_v1430_IEs_oms_1[] = { 0, 1, 2, 3 };
static const ber_tlv_tag_t asn_DEF_SystemInformationBlockType1_v1430_IEs_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_SystemInformationBlockType1_v1430_IEs_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* eCallOverIMS-Support-r14 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* tdd-Config-v1430 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* cellAccessRelatedInfoList-r14 */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 } /* nonCriticalExtension */
};
asn_SEQUENCE_specifics_t asn_SPC_SystemInformationBlockType1_v1430_IEs_specs_1 = {
	sizeof(struct SystemInformationBlockType1_v1430_IEs),
	offsetof(struct SystemInformationBlockType1_v1430_IEs, _asn_ctx),
	asn_MAP_SystemInformationBlockType1_v1430_IEs_tag2el_1,
	4,	/* Count of tags in the map */
	asn_MAP_SystemInformationBlockType1_v1430_IEs_oms_1,	/* Optional members */
	4, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_SystemInformationBlockType1_v1430_IEs = {
	"SystemInformationBlockType1-v1430-IEs",
	"SystemInformationBlockType1-v1430-IEs",
	&asn_OP_SEQUENCE,
	asn_DEF_SystemInformationBlockType1_v1430_IEs_tags_1,
	sizeof(asn_DEF_SystemInformationBlockType1_v1430_IEs_tags_1)
		/sizeof(asn_DEF_SystemInformationBlockType1_v1430_IEs_tags_1[0]), /* 1 */
	asn_DEF_SystemInformationBlockType1_v1430_IEs_tags_1,	/* Same as above */
	sizeof(asn_DEF_SystemInformationBlockType1_v1430_IEs_tags_1)
		/sizeof(asn_DEF_SystemInformationBlockType1_v1430_IEs_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_SystemInformationBlockType1_v1430_IEs_1,
	4,	/* Elements count */
	&asn_SPC_SystemInformationBlockType1_v1430_IEs_specs_1	/* Additional specs */
};
