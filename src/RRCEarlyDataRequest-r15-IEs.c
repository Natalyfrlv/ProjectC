/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "rrc.asn1"
 * 	`asn1c -fcompound-names -no-gen-example -gen-PER -pdu=RRCConnectionSetup -D src`
 */

#include "RRCEarlyDataRequest-r15-IEs.h"

/*
 * This type is implemented using NativeEnumerated,
 * so here we adjust the DEF accordingly.
 */
static asn_oer_constraints_t asn_OER_type_establishmentCause_r15_constr_3 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_establishmentCause_r15_constr_3 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static const asn_INTEGER_enum_map_t asn_MAP_establishmentCause_r15_value2enum_3[] = {
	{ 0,	11,	"mo-Data-r15" },
	{ 1,	23,	"delayTolerantAccess-r15" }
};
static const unsigned int asn_MAP_establishmentCause_r15_enum2value_3[] = {
	1,	/* delayTolerantAccess-r15(1) */
	0	/* mo-Data-r15(0) */
};
static const asn_INTEGER_specifics_t asn_SPC_establishmentCause_r15_specs_3 = {
	asn_MAP_establishmentCause_r15_value2enum_3,	/* "tag" => N; sorted by tag */
	asn_MAP_establishmentCause_r15_enum2value_3,	/* N => "tag"; sorted by N */
	2,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_establishmentCause_r15_tags_3[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_establishmentCause_r15_3 = {
	"establishmentCause-r15",
	"establishmentCause-r15",
	&asn_OP_NativeEnumerated,
	asn_DEF_establishmentCause_r15_tags_3,
	sizeof(asn_DEF_establishmentCause_r15_tags_3)
		/sizeof(asn_DEF_establishmentCause_r15_tags_3[0]) - 1, /* 1 */
	asn_DEF_establishmentCause_r15_tags_3,	/* Same as above */
	sizeof(asn_DEF_establishmentCause_r15_tags_3)
		/sizeof(asn_DEF_establishmentCause_r15_tags_3[0]), /* 2 */
	{ &asn_OER_type_establishmentCause_r15_constr_3, &asn_PER_type_establishmentCause_r15_constr_3, NativeEnumerated_constraint },
	0, 0,	/* Defined elsewhere */
	&asn_SPC_establishmentCause_r15_specs_3	/* Additional specs */
};

static const ber_tlv_tag_t asn_DEF_nonCriticalExtension_tags_7[] = {
	(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_SEQUENCE_specifics_t asn_SPC_nonCriticalExtension_specs_7 = {
	sizeof(struct RRCEarlyDataRequest_r15_IEs__nonCriticalExtension),
	offsetof(struct RRCEarlyDataRequest_r15_IEs__nonCriticalExtension, _asn_ctx),
	0,	/* No top level tags */
	0,	/* No tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_nonCriticalExtension_7 = {
	"nonCriticalExtension",
	"nonCriticalExtension",
	&asn_OP_SEQUENCE,
	asn_DEF_nonCriticalExtension_tags_7,
	sizeof(asn_DEF_nonCriticalExtension_tags_7)
		/sizeof(asn_DEF_nonCriticalExtension_tags_7[0]) - 1, /* 1 */
	asn_DEF_nonCriticalExtension_tags_7,	/* Same as above */
	sizeof(asn_DEF_nonCriticalExtension_tags_7)
		/sizeof(asn_DEF_nonCriticalExtension_tags_7[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	0, 0,	/* No members */
	&asn_SPC_nonCriticalExtension_specs_7	/* Additional specs */
};

asn_TYPE_member_t asn_MBR_RRCEarlyDataRequest_r15_IEs_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct RRCEarlyDataRequest_r15_IEs, s_TMSI_r15),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_S_TMSI,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"s-TMSI-r15"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct RRCEarlyDataRequest_r15_IEs, establishmentCause_r15),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_establishmentCause_r15_3,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"establishmentCause-r15"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct RRCEarlyDataRequest_r15_IEs, dedicatedInfoNAS_r15),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_DedicatedInfoNAS,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"dedicatedInfoNAS-r15"
		},
	{ ATF_POINTER, 1, offsetof(struct RRCEarlyDataRequest_r15_IEs, nonCriticalExtension),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		0,
		&asn_DEF_nonCriticalExtension_7,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"nonCriticalExtension"
		},
};
static const int asn_MAP_RRCEarlyDataRequest_r15_IEs_oms_1[] = { 3 };
static const ber_tlv_tag_t asn_DEF_RRCEarlyDataRequest_r15_IEs_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_RRCEarlyDataRequest_r15_IEs_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* s-TMSI-r15 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* establishmentCause-r15 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* dedicatedInfoNAS-r15 */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 } /* nonCriticalExtension */
};
asn_SEQUENCE_specifics_t asn_SPC_RRCEarlyDataRequest_r15_IEs_specs_1 = {
	sizeof(struct RRCEarlyDataRequest_r15_IEs),
	offsetof(struct RRCEarlyDataRequest_r15_IEs, _asn_ctx),
	asn_MAP_RRCEarlyDataRequest_r15_IEs_tag2el_1,
	4,	/* Count of tags in the map */
	asn_MAP_RRCEarlyDataRequest_r15_IEs_oms_1,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_RRCEarlyDataRequest_r15_IEs = {
	"RRCEarlyDataRequest-r15-IEs",
	"RRCEarlyDataRequest-r15-IEs",
	&asn_OP_SEQUENCE,
	asn_DEF_RRCEarlyDataRequest_r15_IEs_tags_1,
	sizeof(asn_DEF_RRCEarlyDataRequest_r15_IEs_tags_1)
		/sizeof(asn_DEF_RRCEarlyDataRequest_r15_IEs_tags_1[0]), /* 1 */
	asn_DEF_RRCEarlyDataRequest_r15_IEs_tags_1,	/* Same as above */
	sizeof(asn_DEF_RRCEarlyDataRequest_r15_IEs_tags_1)
		/sizeof(asn_DEF_RRCEarlyDataRequest_r15_IEs_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_RRCEarlyDataRequest_r15_IEs_1,
	4,	/* Elements count */
	&asn_SPC_RRCEarlyDataRequest_r15_IEs_specs_1	/* Additional specs */
};

