/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "rrc.asn1"
 * 	`asn1c -fcompound-names -no-gen-example -gen-PER -pdu=RRCConnectionSetup -D src`
 */

#include "SL-DiscTxResourceInfoPerFreq-r13.h"

asn_TYPE_member_t asn_MBR_SL_DiscTxResourceInfoPerFreq_r13_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct SL_DiscTxResourceInfoPerFreq_r13, discTxCarrierFreq_r13),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_ARFCN_ValueEUTRA_r9,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"discTxCarrierFreq-r13"
		},
	{ ATF_POINTER, 4, offsetof(struct SL_DiscTxResourceInfoPerFreq_r13, discTxResources_r13),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_SL_DiscTxResource_r13,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"discTxResources-r13"
		},
	{ ATF_POINTER, 3, offsetof(struct SL_DiscTxResourceInfoPerFreq_r13, discTxResourcesPS_r13),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_SL_DiscTxResource_r13,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"discTxResourcesPS-r13"
		},
	{ ATF_POINTER, 2, offsetof(struct SL_DiscTxResourceInfoPerFreq_r13, discTxRefCarrierDedicated_r13),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_SL_DiscTxRefCarrierDedicated_r13,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"discTxRefCarrierDedicated-r13"
		},
	{ ATF_POINTER, 1, offsetof(struct SL_DiscTxResourceInfoPerFreq_r13, discCellSelectionInfo_r13),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_CellSelectionInfoNFreq_r13,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"discCellSelectionInfo-r13"
		},
};
static const int asn_MAP_SL_DiscTxResourceInfoPerFreq_r13_oms_1[] = { 1, 2, 3, 4 };
static const ber_tlv_tag_t asn_DEF_SL_DiscTxResourceInfoPerFreq_r13_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_SL_DiscTxResourceInfoPerFreq_r13_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* discTxCarrierFreq-r13 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* discTxResources-r13 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* discTxResourcesPS-r13 */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* discTxRefCarrierDedicated-r13 */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 } /* discCellSelectionInfo-r13 */
};
asn_SEQUENCE_specifics_t asn_SPC_SL_DiscTxResourceInfoPerFreq_r13_specs_1 = {
	sizeof(struct SL_DiscTxResourceInfoPerFreq_r13),
	offsetof(struct SL_DiscTxResourceInfoPerFreq_r13, _asn_ctx),
	asn_MAP_SL_DiscTxResourceInfoPerFreq_r13_tag2el_1,
	5,	/* Count of tags in the map */
	asn_MAP_SL_DiscTxResourceInfoPerFreq_r13_oms_1,	/* Optional members */
	4, 0,	/* Root/Additions */
	5,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_SL_DiscTxResourceInfoPerFreq_r13 = {
	"SL-DiscTxResourceInfoPerFreq-r13",
	"SL-DiscTxResourceInfoPerFreq-r13",
	&asn_OP_SEQUENCE,
	asn_DEF_SL_DiscTxResourceInfoPerFreq_r13_tags_1,
	sizeof(asn_DEF_SL_DiscTxResourceInfoPerFreq_r13_tags_1)
		/sizeof(asn_DEF_SL_DiscTxResourceInfoPerFreq_r13_tags_1[0]), /* 1 */
	asn_DEF_SL_DiscTxResourceInfoPerFreq_r13_tags_1,	/* Same as above */
	sizeof(asn_DEF_SL_DiscTxResourceInfoPerFreq_r13_tags_1)
		/sizeof(asn_DEF_SL_DiscTxResourceInfoPerFreq_r13_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_SL_DiscTxResourceInfoPerFreq_r13_1,
	5,	/* Elements count */
	&asn_SPC_SL_DiscTxResourceInfoPerFreq_r13_specs_1	/* Additional specs */
};

