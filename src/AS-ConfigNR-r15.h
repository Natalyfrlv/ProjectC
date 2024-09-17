/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-InterNodeDefinitions"
 * 	found in "rrc.asn1"
 * 	`asn1c -fcompound-names -no-gen-example -gen-PER -pdu=RRCConnectionSetup -D src`
 */

#ifndef	_AS_ConfigNR_r15_H_
#define	_AS_ConfigNR_r15_H_


#include <asn_application.h>

/* Including external dependencies */
#include <OCTET_STRING.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* AS-ConfigNR-r15 */
typedef struct AS_ConfigNR_r15 {
	OCTET_STRING_t	*sourceRB_ConfigNR_r15	/* OPTIONAL */;
	OCTET_STRING_t	*sourceRB_ConfigSN_NR_r15	/* OPTIONAL */;
	OCTET_STRING_t	*sourceOtherConfigSN_NR_r15	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} AS_ConfigNR_r15_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_AS_ConfigNR_r15;
extern asn_SEQUENCE_specifics_t asn_SPC_AS_ConfigNR_r15_specs_1;
extern asn_TYPE_member_t asn_MBR_AS_ConfigNR_r15_1[3];

#ifdef __cplusplus
}
#endif

#endif	/* _AS_ConfigNR_r15_H_ */
#include <asn_internal.h>