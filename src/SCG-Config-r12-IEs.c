/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-InterNodeDefinitions"
 * 	found in "rrc.asn1"
 * 	`asn1c -fcompound-names -no-gen-example -gen-PER -pdu=RRCConnectionSetup -D src`
 */

#include "SCG-Config-r12-IEs.h"

asn_TYPE_member_t asn_MBR_SCG_Config_r12_IEs_1[] = {
	{ ATF_POINTER, 2, offsetof(struct SCG_Config_r12_IEs, scg_RadioConfig_r12),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_SCG_ConfigPartSCG_r12,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"scg-RadioConfig-r12"
		},
	{ ATF_POINTER, 1, offsetof(struct SCG_Config_r12_IEs, nonCriticalExtension),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_SCG_Config_v12x0_IEs,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"nonCriticalExtension"
		},
};
static const int asn_MAP_SCG_Config_r12_IEs_oms_1[] = { 0, 1 };
static const ber_tlv_tag_t asn_DEF_SCG_Config_r12_IEs_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_SCG_Config_r12_IEs_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* scg-RadioConfig-r12 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* nonCriticalExtension */
};
asn_SEQUENCE_specifics_t asn_SPC_SCG_Config_r12_IEs_specs_1 = {
	sizeof(struct SCG_Config_r12_IEs),
	offsetof(struct SCG_Config_r12_IEs, _asn_ctx),
	asn_MAP_SCG_Config_r12_IEs_tag2el_1,
	2,	/* Count of tags in the map */
	asn_MAP_SCG_Config_r12_IEs_oms_1,	/* Optional members */
	2, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_SCG_Config_r12_IEs = {
	"SCG-Config-r12-IEs",
	"SCG-Config-r12-IEs",
	&asn_OP_SEQUENCE,
	asn_DEF_SCG_Config_r12_IEs_tags_1,
	sizeof(asn_DEF_SCG_Config_r12_IEs_tags_1)
		/sizeof(asn_DEF_SCG_Config_r12_IEs_tags_1[0]), /* 1 */
	asn_DEF_SCG_Config_r12_IEs_tags_1,	/* Same as above */
	sizeof(asn_DEF_SCG_Config_r12_IEs_tags_1)
		/sizeof(asn_DEF_SCG_Config_r12_IEs_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_SCG_Config_r12_IEs_1,
	2,	/* Elements count */
	&asn_SPC_SCG_Config_r12_IEs_specs_1	/* Additional specs */
};

