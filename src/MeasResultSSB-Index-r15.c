/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "rrc.asn1"
 * 	`asn1c -fcompound-names -no-gen-example -gen-PER -pdu=RRCConnectionSetup -D src`
 */

#include "MeasResultSSB-Index-r15.h"

asn_TYPE_member_t asn_MBR_MeasResultSSB_Index_r15_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct MeasResultSSB_Index_r15, ssb_Index_r15),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RS_IndexNR_r15,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"ssb-Index-r15"
		},
	{ ATF_POINTER, 1, offsetof(struct MeasResultSSB_Index_r15, measResultSSB_Index_r15),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MeasResultNR_r15,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"measResultSSB-Index-r15"
		},
};
static const int asn_MAP_MeasResultSSB_Index_r15_oms_1[] = { 1 };
static const ber_tlv_tag_t asn_DEF_MeasResultSSB_Index_r15_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_MeasResultSSB_Index_r15_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* ssb-Index-r15 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* measResultSSB-Index-r15 */
};
asn_SEQUENCE_specifics_t asn_SPC_MeasResultSSB_Index_r15_specs_1 = {
	sizeof(struct MeasResultSSB_Index_r15),
	offsetof(struct MeasResultSSB_Index_r15, _asn_ctx),
	asn_MAP_MeasResultSSB_Index_r15_tag2el_1,
	2,	/* Count of tags in the map */
	asn_MAP_MeasResultSSB_Index_r15_oms_1,	/* Optional members */
	1, 0,	/* Root/Additions */
	2,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_MeasResultSSB_Index_r15 = {
	"MeasResultSSB-Index-r15",
	"MeasResultSSB-Index-r15",
	&asn_OP_SEQUENCE,
	asn_DEF_MeasResultSSB_Index_r15_tags_1,
	sizeof(asn_DEF_MeasResultSSB_Index_r15_tags_1)
		/sizeof(asn_DEF_MeasResultSSB_Index_r15_tags_1[0]), /* 1 */
	asn_DEF_MeasResultSSB_Index_r15_tags_1,	/* Same as above */
	sizeof(asn_DEF_MeasResultSSB_Index_r15_tags_1)
		/sizeof(asn_DEF_MeasResultSSB_Index_r15_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_MeasResultSSB_Index_r15_1,
	2,	/* Elements count */
	&asn_SPC_MeasResultSSB_Index_r15_specs_1	/* Additional specs */
};

