/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "rrc.asn1"
 * 	`asn1c -fcompound-names -no-gen-example -gen-PER -pdu=RRCConnectionSetup -D src`
 */

#include "SL-CommConfig-r12.h"

static int
memb_mcs_r12_constraint_5(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= 0 && value <= 28)) {
		/* Constraint check succeeded */
		return 0;
	} else {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static asn_oer_constraints_t asn_OER_memb_mcs_r12_constr_9 CC_NOTUSED = {
	{ 1, 1 }	/* (0..28) */,
	-1};
static asn_per_constraints_t asn_PER_memb_mcs_r12_constr_9 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 5,  5,  0,  28 }	/* (0..28) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_type_setup_constr_4 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_setup_constr_4 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_type_commTxResources_r12_constr_2 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_commTxResources_r12_constr_2 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_type_setup_constr_17 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_setup_constr_17 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_type_commTxResources_v1310_constr_15 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_commTxResources_v1310_constr_15 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_scheduled_r12_5[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct SL_CommConfig_r12__commTxResources_r12__setup__scheduled_r12, sl_RNTI_r12),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_C_RNTI,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"sl-RNTI-r12"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SL_CommConfig_r12__commTxResources_r12__setup__scheduled_r12, mac_MainConfig_r12),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MAC_MainConfigSL_r12,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"mac-MainConfig-r12"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SL_CommConfig_r12__commTxResources_r12__setup__scheduled_r12, sc_CommTxConfig_r12),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_SL_CommResourcePool_r12,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"sc-CommTxConfig-r12"
		},
	{ ATF_POINTER, 1, offsetof(struct SL_CommConfig_r12__commTxResources_r12__setup__scheduled_r12, mcs_r12),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		0,
		{ &asn_OER_memb_mcs_r12_constr_9, &asn_PER_memb_mcs_r12_constr_9,  memb_mcs_r12_constraint_5 },
		0, 0, /* No default value */
		"mcs-r12"
		},
};
static const int asn_MAP_scheduled_r12_oms_5[] = { 3 };
static const ber_tlv_tag_t asn_DEF_scheduled_r12_tags_5[] = {
	(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_scheduled_r12_tag2el_5[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* sl-RNTI-r12 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* mac-MainConfig-r12 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* sc-CommTxConfig-r12 */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 } /* mcs-r12 */
};
static asn_SEQUENCE_specifics_t asn_SPC_scheduled_r12_specs_5 = {
	sizeof(struct SL_CommConfig_r12__commTxResources_r12__setup__scheduled_r12),
	offsetof(struct SL_CommConfig_r12__commTxResources_r12__setup__scheduled_r12, _asn_ctx),
	asn_MAP_scheduled_r12_tag2el_5,
	4,	/* Count of tags in the map */
	asn_MAP_scheduled_r12_oms_5,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_scheduled_r12_5 = {
	"scheduled-r12",
	"scheduled-r12",
	&asn_OP_SEQUENCE,
	asn_DEF_scheduled_r12_tags_5,
	sizeof(asn_DEF_scheduled_r12_tags_5)
		/sizeof(asn_DEF_scheduled_r12_tags_5[0]) - 1, /* 1 */
	asn_DEF_scheduled_r12_tags_5,	/* Same as above */
	sizeof(asn_DEF_scheduled_r12_tags_5)
		/sizeof(asn_DEF_scheduled_r12_tags_5[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_scheduled_r12_5,
	4,	/* Elements count */
	&asn_SPC_scheduled_r12_specs_5	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_commTxPoolNormalDedicated_r12_11[] = {
	{ ATF_POINTER, 2, offsetof(struct SL_CommConfig_r12__commTxResources_r12__setup__ue_Selected_r12__commTxPoolNormalDedicated_r12, poolToReleaseList_r12),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_SL_TxPoolToReleaseList_r12,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"poolToReleaseList-r12"
		},
	{ ATF_POINTER, 1, offsetof(struct SL_CommConfig_r12__commTxResources_r12__setup__ue_Selected_r12__commTxPoolNormalDedicated_r12, poolToAddModList_r12),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_SL_CommTxPoolToAddModList_r12,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"poolToAddModList-r12"
		},
};
static const int asn_MAP_commTxPoolNormalDedicated_r12_oms_11[] = { 0, 1 };
static const ber_tlv_tag_t asn_DEF_commTxPoolNormalDedicated_r12_tags_11[] = {
	(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_commTxPoolNormalDedicated_r12_tag2el_11[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* poolToReleaseList-r12 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* poolToAddModList-r12 */
};
static asn_SEQUENCE_specifics_t asn_SPC_commTxPoolNormalDedicated_r12_specs_11 = {
	sizeof(struct SL_CommConfig_r12__commTxResources_r12__setup__ue_Selected_r12__commTxPoolNormalDedicated_r12),
	offsetof(struct SL_CommConfig_r12__commTxResources_r12__setup__ue_Selected_r12__commTxPoolNormalDedicated_r12, _asn_ctx),
	asn_MAP_commTxPoolNormalDedicated_r12_tag2el_11,
	2,	/* Count of tags in the map */
	asn_MAP_commTxPoolNormalDedicated_r12_oms_11,	/* Optional members */
	2, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_commTxPoolNormalDedicated_r12_11 = {
	"commTxPoolNormalDedicated-r12",
	"commTxPoolNormalDedicated-r12",
	&asn_OP_SEQUENCE,
	asn_DEF_commTxPoolNormalDedicated_r12_tags_11,
	sizeof(asn_DEF_commTxPoolNormalDedicated_r12_tags_11)
		/sizeof(asn_DEF_commTxPoolNormalDedicated_r12_tags_11[0]) - 1, /* 1 */
	asn_DEF_commTxPoolNormalDedicated_r12_tags_11,	/* Same as above */
	sizeof(asn_DEF_commTxPoolNormalDedicated_r12_tags_11)
		/sizeof(asn_DEF_commTxPoolNormalDedicated_r12_tags_11[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_commTxPoolNormalDedicated_r12_11,
	2,	/* Elements count */
	&asn_SPC_commTxPoolNormalDedicated_r12_specs_11	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_ue_Selected_r12_10[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct SL_CommConfig_r12__commTxResources_r12__setup__ue_Selected_r12, commTxPoolNormalDedicated_r12),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		0,
		&asn_DEF_commTxPoolNormalDedicated_r12_11,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"commTxPoolNormalDedicated-r12"
		},
};
static const ber_tlv_tag_t asn_DEF_ue_Selected_r12_tags_10[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_ue_Selected_r12_tag2el_10[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 } /* commTxPoolNormalDedicated-r12 */
};
static asn_SEQUENCE_specifics_t asn_SPC_ue_Selected_r12_specs_10 = {
	sizeof(struct SL_CommConfig_r12__commTxResources_r12__setup__ue_Selected_r12),
	offsetof(struct SL_CommConfig_r12__commTxResources_r12__setup__ue_Selected_r12, _asn_ctx),
	asn_MAP_ue_Selected_r12_tag2el_10,
	1,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_ue_Selected_r12_10 = {
	"ue-Selected-r12",
	"ue-Selected-r12",
	&asn_OP_SEQUENCE,
	asn_DEF_ue_Selected_r12_tags_10,
	sizeof(asn_DEF_ue_Selected_r12_tags_10)
		/sizeof(asn_DEF_ue_Selected_r12_tags_10[0]) - 1, /* 1 */
	asn_DEF_ue_Selected_r12_tags_10,	/* Same as above */
	sizeof(asn_DEF_ue_Selected_r12_tags_10)
		/sizeof(asn_DEF_ue_Selected_r12_tags_10[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_ue_Selected_r12_10,
	1,	/* Elements count */
	&asn_SPC_ue_Selected_r12_specs_10	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_setup_4[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct SL_CommConfig_r12__commTxResources_r12__setup, choice.scheduled_r12),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		0,
		&asn_DEF_scheduled_r12_5,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"scheduled-r12"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SL_CommConfig_r12__commTxResources_r12__setup, choice.ue_Selected_r12),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		0,
		&asn_DEF_ue_Selected_r12_10,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"ue-Selected-r12"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_setup_tag2el_4[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* scheduled-r12 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* ue-Selected-r12 */
};
static asn_CHOICE_specifics_t asn_SPC_setup_specs_4 = {
	sizeof(struct SL_CommConfig_r12__commTxResources_r12__setup),
	offsetof(struct SL_CommConfig_r12__commTxResources_r12__setup, _asn_ctx),
	offsetof(struct SL_CommConfig_r12__commTxResources_r12__setup, present),
	sizeof(((struct SL_CommConfig_r12__commTxResources_r12__setup *)0)->present),
	asn_MAP_setup_tag2el_4,
	2,	/* Count of tags in the map */
	0, 0,
	-1	/* Extensions start */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_setup_4 = {
	"setup",
	"setup",
	&asn_OP_CHOICE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ &asn_OER_type_setup_constr_4, &asn_PER_type_setup_constr_4, CHOICE_constraint },
	asn_MBR_setup_4,
	2,	/* Elements count */
	&asn_SPC_setup_specs_4	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_commTxResources_r12_2[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct SL_CommConfig_r12__commTxResources_r12, choice.release),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"release"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SL_CommConfig_r12__commTxResources_r12, choice.setup),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_setup_4,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"setup"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_commTxResources_r12_tag2el_2[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* release */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* setup */
};
static asn_CHOICE_specifics_t asn_SPC_commTxResources_r12_specs_2 = {
	sizeof(struct SL_CommConfig_r12__commTxResources_r12),
	offsetof(struct SL_CommConfig_r12__commTxResources_r12, _asn_ctx),
	offsetof(struct SL_CommConfig_r12__commTxResources_r12, present),
	sizeof(((struct SL_CommConfig_r12__commTxResources_r12 *)0)->present),
	asn_MAP_commTxResources_r12_tag2el_2,
	2,	/* Count of tags in the map */
	0, 0,
	-1	/* Extensions start */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_commTxResources_r12_2 = {
	"commTxResources-r12",
	"commTxResources-r12",
	&asn_OP_CHOICE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ &asn_OER_type_commTxResources_r12_constr_2, &asn_PER_type_commTxResources_r12_constr_2, CHOICE_constraint },
	asn_MBR_commTxResources_r12_2,
	2,	/* Elements count */
	&asn_SPC_commTxResources_r12_specs_2	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_scheduled_v1310_18[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct SL_CommConfig_r12__commTxResources_v1310__setup__scheduled_v1310, logicalChGroupInfoList_r13),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LogicalChGroupInfoList_r13,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"logicalChGroupInfoList-r13"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SL_CommConfig_r12__commTxResources_v1310__setup__scheduled_v1310, multipleTx_r13),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_BOOLEAN,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"multipleTx-r13"
		},
};
static const ber_tlv_tag_t asn_DEF_scheduled_v1310_tags_18[] = {
	(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_scheduled_v1310_tag2el_18[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* logicalChGroupInfoList-r13 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* multipleTx-r13 */
};
static asn_SEQUENCE_specifics_t asn_SPC_scheduled_v1310_specs_18 = {
	sizeof(struct SL_CommConfig_r12__commTxResources_v1310__setup__scheduled_v1310),
	offsetof(struct SL_CommConfig_r12__commTxResources_v1310__setup__scheduled_v1310, _asn_ctx),
	asn_MAP_scheduled_v1310_tag2el_18,
	2,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_scheduled_v1310_18 = {
	"scheduled-v1310",
	"scheduled-v1310",
	&asn_OP_SEQUENCE,
	asn_DEF_scheduled_v1310_tags_18,
	sizeof(asn_DEF_scheduled_v1310_tags_18)
		/sizeof(asn_DEF_scheduled_v1310_tags_18[0]) - 1, /* 1 */
	asn_DEF_scheduled_v1310_tags_18,	/* Same as above */
	sizeof(asn_DEF_scheduled_v1310_tags_18)
		/sizeof(asn_DEF_scheduled_v1310_tags_18[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_scheduled_v1310_18,
	2,	/* Elements count */
	&asn_SPC_scheduled_v1310_specs_18	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_commTxPoolNormalDedicatedExt_r13_22[] = {
	{ ATF_POINTER, 2, offsetof(struct SL_CommConfig_r12__commTxResources_v1310__setup__ue_Selected_v1310__commTxPoolNormalDedicatedExt_r13, poolToReleaseListExt_r13),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_SL_TxPoolToReleaseListExt_r13,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"poolToReleaseListExt-r13"
		},
	{ ATF_POINTER, 1, offsetof(struct SL_CommConfig_r12__commTxResources_v1310__setup__ue_Selected_v1310__commTxPoolNormalDedicatedExt_r13, poolToAddModListExt_r13),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_SL_CommTxPoolToAddModListExt_r13,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"poolToAddModListExt-r13"
		},
};
static const int asn_MAP_commTxPoolNormalDedicatedExt_r13_oms_22[] = { 0, 1 };
static const ber_tlv_tag_t asn_DEF_commTxPoolNormalDedicatedExt_r13_tags_22[] = {
	(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_commTxPoolNormalDedicatedExt_r13_tag2el_22[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* poolToReleaseListExt-r13 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* poolToAddModListExt-r13 */
};
static asn_SEQUENCE_specifics_t asn_SPC_commTxPoolNormalDedicatedExt_r13_specs_22 = {
	sizeof(struct SL_CommConfig_r12__commTxResources_v1310__setup__ue_Selected_v1310__commTxPoolNormalDedicatedExt_r13),
	offsetof(struct SL_CommConfig_r12__commTxResources_v1310__setup__ue_Selected_v1310__commTxPoolNormalDedicatedExt_r13, _asn_ctx),
	asn_MAP_commTxPoolNormalDedicatedExt_r13_tag2el_22,
	2,	/* Count of tags in the map */
	asn_MAP_commTxPoolNormalDedicatedExt_r13_oms_22,	/* Optional members */
	2, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_commTxPoolNormalDedicatedExt_r13_22 = {
	"commTxPoolNormalDedicatedExt-r13",
	"commTxPoolNormalDedicatedExt-r13",
	&asn_OP_SEQUENCE,
	asn_DEF_commTxPoolNormalDedicatedExt_r13_tags_22,
	sizeof(asn_DEF_commTxPoolNormalDedicatedExt_r13_tags_22)
		/sizeof(asn_DEF_commTxPoolNormalDedicatedExt_r13_tags_22[0]) - 1, /* 1 */
	asn_DEF_commTxPoolNormalDedicatedExt_r13_tags_22,	/* Same as above */
	sizeof(asn_DEF_commTxPoolNormalDedicatedExt_r13_tags_22)
		/sizeof(asn_DEF_commTxPoolNormalDedicatedExt_r13_tags_22[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_commTxPoolNormalDedicatedExt_r13_22,
	2,	/* Elements count */
	&asn_SPC_commTxPoolNormalDedicatedExt_r13_specs_22	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_ue_Selected_v1310_21[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct SL_CommConfig_r12__commTxResources_v1310__setup__ue_Selected_v1310, commTxPoolNormalDedicatedExt_r13),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		0,
		&asn_DEF_commTxPoolNormalDedicatedExt_r13_22,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"commTxPoolNormalDedicatedExt-r13"
		},
};
static const ber_tlv_tag_t asn_DEF_ue_Selected_v1310_tags_21[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_ue_Selected_v1310_tag2el_21[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 } /* commTxPoolNormalDedicatedExt-r13 */
};
static asn_SEQUENCE_specifics_t asn_SPC_ue_Selected_v1310_specs_21 = {
	sizeof(struct SL_CommConfig_r12__commTxResources_v1310__setup__ue_Selected_v1310),
	offsetof(struct SL_CommConfig_r12__commTxResources_v1310__setup__ue_Selected_v1310, _asn_ctx),
	asn_MAP_ue_Selected_v1310_tag2el_21,
	1,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_ue_Selected_v1310_21 = {
	"ue-Selected-v1310",
	"ue-Selected-v1310",
	&asn_OP_SEQUENCE,
	asn_DEF_ue_Selected_v1310_tags_21,
	sizeof(asn_DEF_ue_Selected_v1310_tags_21)
		/sizeof(asn_DEF_ue_Selected_v1310_tags_21[0]) - 1, /* 1 */
	asn_DEF_ue_Selected_v1310_tags_21,	/* Same as above */
	sizeof(asn_DEF_ue_Selected_v1310_tags_21)
		/sizeof(asn_DEF_ue_Selected_v1310_tags_21[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_ue_Selected_v1310_21,
	1,	/* Elements count */
	&asn_SPC_ue_Selected_v1310_specs_21	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_setup_17[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct SL_CommConfig_r12__commTxResources_v1310__setup, choice.scheduled_v1310),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		0,
		&asn_DEF_scheduled_v1310_18,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"scheduled-v1310"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SL_CommConfig_r12__commTxResources_v1310__setup, choice.ue_Selected_v1310),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		0,
		&asn_DEF_ue_Selected_v1310_21,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"ue-Selected-v1310"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_setup_tag2el_17[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* scheduled-v1310 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* ue-Selected-v1310 */
};
static asn_CHOICE_specifics_t asn_SPC_setup_specs_17 = {
	sizeof(struct SL_CommConfig_r12__commTxResources_v1310__setup),
	offsetof(struct SL_CommConfig_r12__commTxResources_v1310__setup, _asn_ctx),
	offsetof(struct SL_CommConfig_r12__commTxResources_v1310__setup, present),
	sizeof(((struct SL_CommConfig_r12__commTxResources_v1310__setup *)0)->present),
	asn_MAP_setup_tag2el_17,
	2,	/* Count of tags in the map */
	0, 0,
	-1	/* Extensions start */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_setup_17 = {
	"setup",
	"setup",
	&asn_OP_CHOICE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ &asn_OER_type_setup_constr_17, &asn_PER_type_setup_constr_17, CHOICE_constraint },
	asn_MBR_setup_17,
	2,	/* Elements count */
	&asn_SPC_setup_specs_17	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_commTxResources_v1310_15[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct SL_CommConfig_r12__commTxResources_v1310, choice.release),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"release"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SL_CommConfig_r12__commTxResources_v1310, choice.setup),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_setup_17,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"setup"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_commTxResources_v1310_tag2el_15[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* release */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* setup */
};
static asn_CHOICE_specifics_t asn_SPC_commTxResources_v1310_specs_15 = {
	sizeof(struct SL_CommConfig_r12__commTxResources_v1310),
	offsetof(struct SL_CommConfig_r12__commTxResources_v1310, _asn_ctx),
	offsetof(struct SL_CommConfig_r12__commTxResources_v1310, present),
	sizeof(((struct SL_CommConfig_r12__commTxResources_v1310 *)0)->present),
	asn_MAP_commTxResources_v1310_tag2el_15,
	2,	/* Count of tags in the map */
	0, 0,
	-1	/* Extensions start */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_commTxResources_v1310_15 = {
	"commTxResources-v1310",
	"commTxResources-v1310",
	&asn_OP_CHOICE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ &asn_OER_type_commTxResources_v1310_constr_15, &asn_PER_type_commTxResources_v1310_constr_15, CHOICE_constraint },
	asn_MBR_commTxResources_v1310_15,
	2,	/* Elements count */
	&asn_SPC_commTxResources_v1310_specs_15	/* Additional specs */
};

asn_TYPE_member_t asn_MBR_SL_CommConfig_r12_1[] = {
	{ ATF_POINTER, 3, offsetof(struct SL_CommConfig_r12, commTxResources_r12),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_commTxResources_r12_2,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"commTxResources-r12"
		},
	{ ATF_POINTER, 2, offsetof(struct SL_CommConfig_r12, commTxResources_v1310),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_commTxResources_v1310_15,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"commTxResources-v1310"
		},
	{ ATF_POINTER, 1, offsetof(struct SL_CommConfig_r12, commTxAllowRelayDedicated_r13),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_BOOLEAN,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"commTxAllowRelayDedicated-r13"
		},
};
static const int asn_MAP_SL_CommConfig_r12_oms_1[] = { 0, 1, 2 };
static const ber_tlv_tag_t asn_DEF_SL_CommConfig_r12_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_SL_CommConfig_r12_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* commTxResources-r12 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* commTxResources-v1310 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* commTxAllowRelayDedicated-r13 */
};
asn_SEQUENCE_specifics_t asn_SPC_SL_CommConfig_r12_specs_1 = {
	sizeof(struct SL_CommConfig_r12),
	offsetof(struct SL_CommConfig_r12, _asn_ctx),
	asn_MAP_SL_CommConfig_r12_tag2el_1,
	3,	/* Count of tags in the map */
	asn_MAP_SL_CommConfig_r12_oms_1,	/* Optional members */
	1, 2,	/* Root/Additions */
	1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_SL_CommConfig_r12 = {
	"SL-CommConfig-r12",
	"SL-CommConfig-r12",
	&asn_OP_SEQUENCE,
	asn_DEF_SL_CommConfig_r12_tags_1,
	sizeof(asn_DEF_SL_CommConfig_r12_tags_1)
		/sizeof(asn_DEF_SL_CommConfig_r12_tags_1[0]), /* 1 */
	asn_DEF_SL_CommConfig_r12_tags_1,	/* Same as above */
	sizeof(asn_DEF_SL_CommConfig_r12_tags_1)
		/sizeof(asn_DEF_SL_CommConfig_r12_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_SL_CommConfig_r12_1,
	3,	/* Elements count */
	&asn_SPC_SL_CommConfig_r12_specs_1	/* Additional specs */
};

