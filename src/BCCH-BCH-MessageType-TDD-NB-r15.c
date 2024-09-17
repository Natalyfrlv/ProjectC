/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "NBIOT-RRC-Definitions"
 * 	found in "rrc.asn1"
 * 	`asn1c -fcompound-names -no-gen-example -gen-PER -pdu=RRCConnectionSetup -D src`
 */

#include "BCCH-BCH-MessageType-TDD-NB-r15.h"

/*
 * This type is implemented using MasterInformationBlock_TDD_NB_r15,
 * so here we adjust the DEF accordingly.
 */
static const ber_tlv_tag_t asn_DEF_BCCH_BCH_MessageType_TDD_NB_r15_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
asn_TYPE_descriptor_t asn_DEF_BCCH_BCH_MessageType_TDD_NB_r15 = {
	"BCCH-BCH-MessageType-TDD-NB-r15",
	"BCCH-BCH-MessageType-TDD-NB-r15",
	&asn_OP_SEQUENCE,
	asn_DEF_BCCH_BCH_MessageType_TDD_NB_r15_tags_1,
	sizeof(asn_DEF_BCCH_BCH_MessageType_TDD_NB_r15_tags_1)
		/sizeof(asn_DEF_BCCH_BCH_MessageType_TDD_NB_r15_tags_1[0]), /* 1 */
	asn_DEF_BCCH_BCH_MessageType_TDD_NB_r15_tags_1,	/* Same as above */
	sizeof(asn_DEF_BCCH_BCH_MessageType_TDD_NB_r15_tags_1)
		/sizeof(asn_DEF_BCCH_BCH_MessageType_TDD_NB_r15_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_MasterInformationBlock_TDD_NB_r15_1,
	8,	/* Elements count */
	&asn_SPC_MasterInformationBlock_TDD_NB_r15_specs_1	/* Additional specs */
};

