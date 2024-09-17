/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "rrc.asn1"
 * 	`asn1c -fcompound-names -no-gen-example -gen-PER -pdu=RRCConnectionSetup -D src`
 */

#include "RRCConnectionReconfiguration-v1310-IEs.h"

asn_TYPE_member_t asn_MBR_RRCConnectionReconfiguration_v1310_IEs_1[] = {
	{ ATF_POINTER, 6, offsetof(struct RRCConnectionReconfiguration_v1310_IEs, sCellToReleaseListExt_r13),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_SCellToReleaseListExt_r13,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"sCellToReleaseListExt-r13"
		},
	{ ATF_POINTER, 5, offsetof(struct RRCConnectionReconfiguration_v1310_IEs, sCellToAddModListExt_r13),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_SCellToAddModListExt_r13,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"sCellToAddModListExt-r13"
		},
	{ ATF_POINTER, 4, offsetof(struct RRCConnectionReconfiguration_v1310_IEs, lwa_Configuration_r13),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_LWA_Configuration_r13,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"lwa-Configuration-r13"
		},
	{ ATF_POINTER, 3, offsetof(struct RRCConnectionReconfiguration_v1310_IEs, lwip_Configuration_r13),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_LWIP_Configuration_r13,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"lwip-Configuration-r13"
		},
	{ ATF_POINTER, 2, offsetof(struct RRCConnectionReconfiguration_v1310_IEs, rclwi_Configuration_r13),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_RCLWI_Configuration_r13,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"rclwi-Configuration-r13"
		},
	{ ATF_POINTER, 1, offsetof(struct RRCConnectionReconfiguration_v1310_IEs, nonCriticalExtension),
		(ASN_TAG_CLASS_CONTEXT | (5 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RRCConnectionReconfiguration_v1430_IEs,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"nonCriticalExtension"
		},
};
static const int asn_MAP_RRCConnectionReconfiguration_v1310_IEs_oms_1[] = { 0, 1, 2, 3, 4, 5 };
static const ber_tlv_tag_t asn_DEF_RRCConnectionReconfiguration_v1310_IEs_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_RRCConnectionReconfiguration_v1310_IEs_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* sCellToReleaseListExt-r13 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* sCellToAddModListExt-r13 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* lwa-Configuration-r13 */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* lwip-Configuration-r13 */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 }, /* rclwi-Configuration-r13 */
    { (ASN_TAG_CLASS_CONTEXT | (5 << 2)), 5, 0, 0 } /* nonCriticalExtension */
};
asn_SEQUENCE_specifics_t asn_SPC_RRCConnectionReconfiguration_v1310_IEs_specs_1 = {
	sizeof(struct RRCConnectionReconfiguration_v1310_IEs),
	offsetof(struct RRCConnectionReconfiguration_v1310_IEs, _asn_ctx),
	asn_MAP_RRCConnectionReconfiguration_v1310_IEs_tag2el_1,
	6,	/* Count of tags in the map */
	asn_MAP_RRCConnectionReconfiguration_v1310_IEs_oms_1,	/* Optional members */
	6, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_RRCConnectionReconfiguration_v1310_IEs = {
	"RRCConnectionReconfiguration-v1310-IEs",
	"RRCConnectionReconfiguration-v1310-IEs",
	&asn_OP_SEQUENCE,
	asn_DEF_RRCConnectionReconfiguration_v1310_IEs_tags_1,
	sizeof(asn_DEF_RRCConnectionReconfiguration_v1310_IEs_tags_1)
		/sizeof(asn_DEF_RRCConnectionReconfiguration_v1310_IEs_tags_1[0]), /* 1 */
	asn_DEF_RRCConnectionReconfiguration_v1310_IEs_tags_1,	/* Same as above */
	sizeof(asn_DEF_RRCConnectionReconfiguration_v1310_IEs_tags_1)
		/sizeof(asn_DEF_RRCConnectionReconfiguration_v1310_IEs_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_RRCConnectionReconfiguration_v1310_IEs_1,
	6,	/* Elements count */
	&asn_SPC_RRCConnectionReconfiguration_v1310_IEs_specs_1	/* Additional specs */
};

