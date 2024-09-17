/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "rrc.asn1"
 * 	`asn1c -fcompound-names -no-gen-example -gen-PER -pdu=RRCConnectionSetup -D src`
 */

#include "UEAssistanceInformation-v1450-IEs.h"

asn_TYPE_member_t asn_MBR_UEAssistanceInformation_v1450_IEs_1[] = {
	{ ATF_POINTER, 2, offsetof(struct UEAssistanceInformation_v1450_IEs, overheatingAssistance_r14),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_OverheatingAssistance_r14,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"overheatingAssistance-r14"
		},
	{ ATF_POINTER, 1, offsetof(struct UEAssistanceInformation_v1450_IEs, nonCriticalExtension),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_UEAssistanceInformation_v1530_IEs,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"nonCriticalExtension"
		},
};
static const int asn_MAP_UEAssistanceInformation_v1450_IEs_oms_1[] = { 0, 1 };
static const ber_tlv_tag_t asn_DEF_UEAssistanceInformation_v1450_IEs_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_UEAssistanceInformation_v1450_IEs_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* overheatingAssistance-r14 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* nonCriticalExtension */
};
asn_SEQUENCE_specifics_t asn_SPC_UEAssistanceInformation_v1450_IEs_specs_1 = {
	sizeof(struct UEAssistanceInformation_v1450_IEs),
	offsetof(struct UEAssistanceInformation_v1450_IEs, _asn_ctx),
	asn_MAP_UEAssistanceInformation_v1450_IEs_tag2el_1,
	2,	/* Count of tags in the map */
	asn_MAP_UEAssistanceInformation_v1450_IEs_oms_1,	/* Optional members */
	2, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_UEAssistanceInformation_v1450_IEs = {
	"UEAssistanceInformation-v1450-IEs",
	"UEAssistanceInformation-v1450-IEs",
	&asn_OP_SEQUENCE,
	asn_DEF_UEAssistanceInformation_v1450_IEs_tags_1,
	sizeof(asn_DEF_UEAssistanceInformation_v1450_IEs_tags_1)
		/sizeof(asn_DEF_UEAssistanceInformation_v1450_IEs_tags_1[0]), /* 1 */
	asn_DEF_UEAssistanceInformation_v1450_IEs_tags_1,	/* Same as above */
	sizeof(asn_DEF_UEAssistanceInformation_v1450_IEs_tags_1)
		/sizeof(asn_DEF_UEAssistanceInformation_v1450_IEs_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_UEAssistanceInformation_v1450_IEs_1,
	2,	/* Elements count */
	&asn_SPC_UEAssistanceInformation_v1450_IEs_specs_1	/* Additional specs */
};

