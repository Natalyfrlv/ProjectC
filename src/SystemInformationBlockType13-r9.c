/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "rrc.asn1"
 * 	`asn1c -fcompound-names -no-gen-example -gen-PER -pdu=RRCConnectionSetup -D src`
 */

#include "SystemInformationBlockType13-r9.h"

asn_TYPE_member_t asn_MBR_SystemInformationBlockType13_r9_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct SystemInformationBlockType13_r9, mbsfn_AreaInfoList_r9),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MBSFN_AreaInfoList_r9,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"mbsfn-AreaInfoList-r9"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SystemInformationBlockType13_r9, notificationConfig_r9),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MBMS_NotificationConfig_r9,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"notificationConfig-r9"
		},
	{ ATF_POINTER, 2, offsetof(struct SystemInformationBlockType13_r9, lateNonCriticalExtension),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_OCTET_STRING,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"lateNonCriticalExtension"
		},
	{ ATF_POINTER, 1, offsetof(struct SystemInformationBlockType13_r9, notificationConfig_v1430),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MBMS_NotificationConfig_v1430,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"notificationConfig-v1430"
		},
};
static const int asn_MAP_SystemInformationBlockType13_r9_oms_1[] = { 2, 3 };
static const ber_tlv_tag_t asn_DEF_SystemInformationBlockType13_r9_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_SystemInformationBlockType13_r9_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* mbsfn-AreaInfoList-r9 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* notificationConfig-r9 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* lateNonCriticalExtension */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 } /* notificationConfig-v1430 */
};
asn_SEQUENCE_specifics_t asn_SPC_SystemInformationBlockType13_r9_specs_1 = {
	sizeof(struct SystemInformationBlockType13_r9),
	offsetof(struct SystemInformationBlockType13_r9, _asn_ctx),
	asn_MAP_SystemInformationBlockType13_r9_tag2el_1,
	4,	/* Count of tags in the map */
	asn_MAP_SystemInformationBlockType13_r9_oms_1,	/* Optional members */
	1, 1,	/* Root/Additions */
	3,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_SystemInformationBlockType13_r9 = {
	"SystemInformationBlockType13-r9",
	"SystemInformationBlockType13-r9",
	&asn_OP_SEQUENCE,
	asn_DEF_SystemInformationBlockType13_r9_tags_1,
	sizeof(asn_DEF_SystemInformationBlockType13_r9_tags_1)
		/sizeof(asn_DEF_SystemInformationBlockType13_r9_tags_1[0]), /* 1 */
	asn_DEF_SystemInformationBlockType13_r9_tags_1,	/* Same as above */
	sizeof(asn_DEF_SystemInformationBlockType13_r9_tags_1)
		/sizeof(asn_DEF_SystemInformationBlockType13_r9_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_SystemInformationBlockType13_r9_1,
	4,	/* Elements count */
	&asn_SPC_SystemInformationBlockType13_r9_specs_1	/* Additional specs */
};

