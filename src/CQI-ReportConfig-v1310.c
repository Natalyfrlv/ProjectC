/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "rrc.asn1"
 * 	`asn1c -fcompound-names -no-gen-example -gen-PER -pdu=RRCConnectionSetup -D src`
 */

#include "CQI-ReportConfig-v1310.h"

asn_TYPE_member_t asn_MBR_CQI_ReportConfig_v1310_1[] = {
	{ ATF_POINTER, 3, offsetof(struct CQI_ReportConfig_v1310, cqi_ReportBoth_v1310),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_CQI_ReportBoth_v1310,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"cqi-ReportBoth-v1310"
		},
	{ ATF_POINTER, 2, offsetof(struct CQI_ReportConfig_v1310, cqi_ReportAperiodic_v1310),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_CQI_ReportAperiodic_v1310,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"cqi-ReportAperiodic-v1310"
		},
	{ ATF_POINTER, 1, offsetof(struct CQI_ReportConfig_v1310, cqi_ReportPeriodic_v1310),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_CQI_ReportPeriodic_v1310,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"cqi-ReportPeriodic-v1310"
		},
};
static const int asn_MAP_CQI_ReportConfig_v1310_oms_1[] = { 0, 1, 2 };
static const ber_tlv_tag_t asn_DEF_CQI_ReportConfig_v1310_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_CQI_ReportConfig_v1310_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* cqi-ReportBoth-v1310 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* cqi-ReportAperiodic-v1310 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* cqi-ReportPeriodic-v1310 */
};
asn_SEQUENCE_specifics_t asn_SPC_CQI_ReportConfig_v1310_specs_1 = {
	sizeof(struct CQI_ReportConfig_v1310),
	offsetof(struct CQI_ReportConfig_v1310, _asn_ctx),
	asn_MAP_CQI_ReportConfig_v1310_tag2el_1,
	3,	/* Count of tags in the map */
	asn_MAP_CQI_ReportConfig_v1310_oms_1,	/* Optional members */
	3, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_CQI_ReportConfig_v1310 = {
	"CQI-ReportConfig-v1310",
	"CQI-ReportConfig-v1310",
	&asn_OP_SEQUENCE,
	asn_DEF_CQI_ReportConfig_v1310_tags_1,
	sizeof(asn_DEF_CQI_ReportConfig_v1310_tags_1)
		/sizeof(asn_DEF_CQI_ReportConfig_v1310_tags_1[0]), /* 1 */
	asn_DEF_CQI_ReportConfig_v1310_tags_1,	/* Same as above */
	sizeof(asn_DEF_CQI_ReportConfig_v1310_tags_1)
		/sizeof(asn_DEF_CQI_ReportConfig_v1310_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_CQI_ReportConfig_v1310_1,
	3,	/* Elements count */
	&asn_SPC_CQI_ReportConfig_v1310_specs_1	/* Additional specs */
};

