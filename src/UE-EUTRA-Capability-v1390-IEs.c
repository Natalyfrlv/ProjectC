/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "rrc.asn1"
 * 	`asn1c -fcompound-names -no-gen-example -gen-PER -pdu=RRCConnectionSetup -D src`
 */

#include "UE-EUTRA-Capability-v1390-IEs.h"

asn_TYPE_member_t asn_MBR_UE_EUTRA_Capability_v1390_IEs_1[] = {
	{ ATF_POINTER, 2, offsetof(struct UE_EUTRA_Capability_v1390_IEs, rf_Parameters_v1390),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RF_Parameters_v1390,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"rf-Parameters-v1390"
		},
	{ ATF_POINTER, 1, offsetof(struct UE_EUTRA_Capability_v1390_IEs, nonCriticalExtension),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_UE_EUTRA_Capability_v13x0_IEs,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"nonCriticalExtension"
		},
};
static const int asn_MAP_UE_EUTRA_Capability_v1390_IEs_oms_1[] = { 0, 1 };
static const ber_tlv_tag_t asn_DEF_UE_EUTRA_Capability_v1390_IEs_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_UE_EUTRA_Capability_v1390_IEs_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* rf-Parameters-v1390 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* nonCriticalExtension */
};
asn_SEQUENCE_specifics_t asn_SPC_UE_EUTRA_Capability_v1390_IEs_specs_1 = {
	sizeof(struct UE_EUTRA_Capability_v1390_IEs),
	offsetof(struct UE_EUTRA_Capability_v1390_IEs, _asn_ctx),
	asn_MAP_UE_EUTRA_Capability_v1390_IEs_tag2el_1,
	2,	/* Count of tags in the map */
	asn_MAP_UE_EUTRA_Capability_v1390_IEs_oms_1,	/* Optional members */
	2, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_UE_EUTRA_Capability_v1390_IEs = {
	"UE-EUTRA-Capability-v1390-IEs",
	"UE-EUTRA-Capability-v1390-IEs",
	&asn_OP_SEQUENCE,
	asn_DEF_UE_EUTRA_Capability_v1390_IEs_tags_1,
	sizeof(asn_DEF_UE_EUTRA_Capability_v1390_IEs_tags_1)
		/sizeof(asn_DEF_UE_EUTRA_Capability_v1390_IEs_tags_1[0]), /* 1 */
	asn_DEF_UE_EUTRA_Capability_v1390_IEs_tags_1,	/* Same as above */
	sizeof(asn_DEF_UE_EUTRA_Capability_v1390_IEs_tags_1)
		/sizeof(asn_DEF_UE_EUTRA_Capability_v1390_IEs_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_UE_EUTRA_Capability_v1390_IEs_1,
	2,	/* Elements count */
	&asn_SPC_UE_EUTRA_Capability_v1390_IEs_specs_1	/* Additional specs */
};

