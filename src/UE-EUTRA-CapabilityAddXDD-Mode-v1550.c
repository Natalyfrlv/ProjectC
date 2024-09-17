/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "rrc.asn1"
 * 	`asn1c -fcompound-names -no-gen-example -gen-PER -pdu=RRCConnectionSetup -D src`
 */

#include "UE-EUTRA-CapabilityAddXDD-Mode-v1550.h"

asn_TYPE_member_t asn_MBR_UE_EUTRA_CapabilityAddXDD_Mode_v1550_1[] = {
	{ ATF_POINTER, 1, offsetof(struct UE_EUTRA_CapabilityAddXDD_Mode_v1550, neighCellSI_AcquisitionParameters_v1550),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NeighCellSI_AcquisitionParameters_v1550,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"neighCellSI-AcquisitionParameters-v1550"
		},
};
static const int asn_MAP_UE_EUTRA_CapabilityAddXDD_Mode_v1550_oms_1[] = { 0 };
static const ber_tlv_tag_t asn_DEF_UE_EUTRA_CapabilityAddXDD_Mode_v1550_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_UE_EUTRA_CapabilityAddXDD_Mode_v1550_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 } /* neighCellSI-AcquisitionParameters-v1550 */
};
asn_SEQUENCE_specifics_t asn_SPC_UE_EUTRA_CapabilityAddXDD_Mode_v1550_specs_1 = {
	sizeof(struct UE_EUTRA_CapabilityAddXDD_Mode_v1550),
	offsetof(struct UE_EUTRA_CapabilityAddXDD_Mode_v1550, _asn_ctx),
	asn_MAP_UE_EUTRA_CapabilityAddXDD_Mode_v1550_tag2el_1,
	1,	/* Count of tags in the map */
	asn_MAP_UE_EUTRA_CapabilityAddXDD_Mode_v1550_oms_1,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_UE_EUTRA_CapabilityAddXDD_Mode_v1550 = {
	"UE-EUTRA-CapabilityAddXDD-Mode-v1550",
	"UE-EUTRA-CapabilityAddXDD-Mode-v1550",
	&asn_OP_SEQUENCE,
	asn_DEF_UE_EUTRA_CapabilityAddXDD_Mode_v1550_tags_1,
	sizeof(asn_DEF_UE_EUTRA_CapabilityAddXDD_Mode_v1550_tags_1)
		/sizeof(asn_DEF_UE_EUTRA_CapabilityAddXDD_Mode_v1550_tags_1[0]), /* 1 */
	asn_DEF_UE_EUTRA_CapabilityAddXDD_Mode_v1550_tags_1,	/* Same as above */
	sizeof(asn_DEF_UE_EUTRA_CapabilityAddXDD_Mode_v1550_tags_1)
		/sizeof(asn_DEF_UE_EUTRA_CapabilityAddXDD_Mode_v1550_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_UE_EUTRA_CapabilityAddXDD_Mode_v1550_1,
	1,	/* Elements count */
	&asn_SPC_UE_EUTRA_CapabilityAddXDD_Mode_v1550_specs_1	/* Additional specs */
};

