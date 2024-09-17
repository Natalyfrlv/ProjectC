/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "rrc.asn1"
 * 	`asn1c -fcompound-names -no-gen-example -gen-PER -pdu=RRCConnectionSetup -D src`
 */

#include "SystemInformation-BR-r13.h"

/*
 * This type is implemented using SystemInformation,
 * so here we adjust the DEF accordingly.
 */
static const ber_tlv_tag_t asn_DEF_SystemInformation_BR_r13_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
asn_TYPE_descriptor_t asn_DEF_SystemInformation_BR_r13 = {
	"SystemInformation-BR-r13",
	"SystemInformation-BR-r13",
	&asn_OP_SEQUENCE,
	asn_DEF_SystemInformation_BR_r13_tags_1,
	sizeof(asn_DEF_SystemInformation_BR_r13_tags_1)
		/sizeof(asn_DEF_SystemInformation_BR_r13_tags_1[0]), /* 1 */
	asn_DEF_SystemInformation_BR_r13_tags_1,	/* Same as above */
	sizeof(asn_DEF_SystemInformation_BR_r13_tags_1)
		/sizeof(asn_DEF_SystemInformation_BR_r13_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_SystemInformation_1,
	1,	/* Elements count */
	&asn_SPC_SystemInformation_specs_1	/* Additional specs */
};

