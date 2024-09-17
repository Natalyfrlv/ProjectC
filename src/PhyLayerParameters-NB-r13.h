/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "NBIOT-RRC-Definitions"
 * 	found in "rrc.asn1"
 * 	`asn1c -fcompound-names -no-gen-example -gen-PER -pdu=RRCConnectionSetup -D src`
 */

#ifndef	_PhyLayerParameters_NB_r13_H_
#define	_PhyLayerParameters_NB_r13_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum PhyLayerParameters_NB_r13__multiTone_r13 {
	PhyLayerParameters_NB_r13__multiTone_r13_supported	= 0
} e_PhyLayerParameters_NB_r13__multiTone_r13;
typedef enum PhyLayerParameters_NB_r13__multiCarrier_r13 {
	PhyLayerParameters_NB_r13__multiCarrier_r13_supported	= 0
} e_PhyLayerParameters_NB_r13__multiCarrier_r13;

/* PhyLayerParameters-NB-r13 */
typedef struct PhyLayerParameters_NB_r13 {
	long	*multiTone_r13	/* OPTIONAL */;
	long	*multiCarrier_r13	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} PhyLayerParameters_NB_r13_t;

/* Implementation */
/* extern asn_TYPE_descriptor_t asn_DEF_multiTone_r13_2;	// (Use -fall-defs-global to expose) */
/* extern asn_TYPE_descriptor_t asn_DEF_multiCarrier_r13_4;	// (Use -fall-defs-global to expose) */
extern asn_TYPE_descriptor_t asn_DEF_PhyLayerParameters_NB_r13;
extern asn_SEQUENCE_specifics_t asn_SPC_PhyLayerParameters_NB_r13_specs_1;
extern asn_TYPE_member_t asn_MBR_PhyLayerParameters_NB_r13_1[2];

#ifdef __cplusplus
}
#endif

#endif	/* _PhyLayerParameters_NB_r13_H_ */
#include <asn_internal.h>
