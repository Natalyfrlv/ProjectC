/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "rrc.asn1"
 * 	`asn1c -fcompound-names -no-gen-example -gen-PER -pdu=RRCConnectionSetup -D src`
 */

#include "SL-CommTxResourceReq-r12.h"

asn_TYPE_member_t asn_MBR_SL_CommTxResourceReq_r12_1[] = {
	{ ATF_POINTER, 1, offsetof(struct SL_CommTxResourceReq_r12, carrierFreq_r12),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_ARFCN_ValueEUTRA_r9,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"carrierFreq-r12"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SL_CommTxResourceReq_r12, destinationInfoList_r12),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_SL_DestinationInfoList_r12,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"destinationInfoList-r12"
		},
};
static const int asn_MAP_SL_CommTxResourceReq_r12_oms_1[] = { 0 };
static const ber_tlv_tag_t asn_DEF_SL_CommTxResourceReq_r12_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_SL_CommTxResourceReq_r12_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* carrierFreq-r12 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* destinationInfoList-r12 */
};
asn_SEQUENCE_specifics_t asn_SPC_SL_CommTxResourceReq_r12_specs_1 = {
	sizeof(struct SL_CommTxResourceReq_r12),
	offsetof(struct SL_CommTxResourceReq_r12, _asn_ctx),
	asn_MAP_SL_CommTxResourceReq_r12_tag2el_1,
	2,	/* Count of tags in the map */
	asn_MAP_SL_CommTxResourceReq_r12_oms_1,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_SL_CommTxResourceReq_r12 = {
	"SL-CommTxResourceReq-r12",
	"SL-CommTxResourceReq-r12",
	&asn_OP_SEQUENCE,
	asn_DEF_SL_CommTxResourceReq_r12_tags_1,
	sizeof(asn_DEF_SL_CommTxResourceReq_r12_tags_1)
		/sizeof(asn_DEF_SL_CommTxResourceReq_r12_tags_1[0]), /* 1 */
	asn_DEF_SL_CommTxResourceReq_r12_tags_1,	/* Same as above */
	sizeof(asn_DEF_SL_CommTxResourceReq_r12_tags_1)
		/sizeof(asn_DEF_SL_CommTxResourceReq_r12_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_SL_CommTxResourceReq_r12_1,
	2,	/* Elements count */
	&asn_SPC_SL_CommTxResourceReq_r12_specs_1	/* Additional specs */
};

