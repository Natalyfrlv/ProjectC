/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "rrc.asn1"
 * 	`asn1c -fcompound-names -no-gen-example -gen-PER -pdu=RRCConnectionSetup -D src`
 */

#include "CSI-RS-ConfigEMIMO-v1480.h"

static asn_oer_constraints_t asn_OER_type_setup_constr_3 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_setup_constr_3 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_type_CSI_RS_ConfigEMIMO_v1480_constr_1 CC_NOTUSED = {
	{ 0, 0 },
	-1};
asn_per_constraints_t asn_PER_type_CSI_RS_ConfigEMIMO_v1480_constr_1 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_setup_3[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct CSI_RS_ConfigEMIMO_v1480__setup, choice.nonPrecoded_v1480),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_CSI_RS_ConfigNonPrecoded_v1480,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"nonPrecoded-v1480"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct CSI_RS_ConfigEMIMO_v1480__setup, choice.beamformed_v1480),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_CSI_RS_ConfigBeamformed_v1430,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"beamformed-v1480"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_setup_tag2el_3[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* nonPrecoded-v1480 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* beamformed-v1480 */
};
static asn_CHOICE_specifics_t asn_SPC_setup_specs_3 = {
	sizeof(struct CSI_RS_ConfigEMIMO_v1480__setup),
	offsetof(struct CSI_RS_ConfigEMIMO_v1480__setup, _asn_ctx),
	offsetof(struct CSI_RS_ConfigEMIMO_v1480__setup, present),
	sizeof(((struct CSI_RS_ConfigEMIMO_v1480__setup *)0)->present),
	asn_MAP_setup_tag2el_3,
	2,	/* Count of tags in the map */
	0, 0,
	-1	/* Extensions start */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_setup_3 = {
	"setup",
	"setup",
	&asn_OP_CHOICE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ &asn_OER_type_setup_constr_3, &asn_PER_type_setup_constr_3, CHOICE_constraint },
	asn_MBR_setup_3,
	2,	/* Elements count */
	&asn_SPC_setup_specs_3	/* Additional specs */
};

asn_TYPE_member_t asn_MBR_CSI_RS_ConfigEMIMO_v1480_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct CSI_RS_ConfigEMIMO_v1480, choice.release),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"release"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct CSI_RS_ConfigEMIMO_v1480, choice.setup),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_setup_3,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"setup"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_CSI_RS_ConfigEMIMO_v1480_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* release */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* setup */
};
asn_CHOICE_specifics_t asn_SPC_CSI_RS_ConfigEMIMO_v1480_specs_1 = {
	sizeof(struct CSI_RS_ConfigEMIMO_v1480),
	offsetof(struct CSI_RS_ConfigEMIMO_v1480, _asn_ctx),
	offsetof(struct CSI_RS_ConfigEMIMO_v1480, present),
	sizeof(((struct CSI_RS_ConfigEMIMO_v1480 *)0)->present),
	asn_MAP_CSI_RS_ConfigEMIMO_v1480_tag2el_1,
	2,	/* Count of tags in the map */
	0, 0,
	-1	/* Extensions start */
};
asn_TYPE_descriptor_t asn_DEF_CSI_RS_ConfigEMIMO_v1480 = {
	"CSI-RS-ConfigEMIMO-v1480",
	"CSI-RS-ConfigEMIMO-v1480",
	&asn_OP_CHOICE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ &asn_OER_type_CSI_RS_ConfigEMIMO_v1480_constr_1, &asn_PER_type_CSI_RS_ConfigEMIMO_v1480_constr_1, CHOICE_constraint },
	asn_MBR_CSI_RS_ConfigEMIMO_v1480_1,
	2,	/* Elements count */
	&asn_SPC_CSI_RS_ConfigEMIMO_v1480_specs_1	/* Additional specs */
};

