/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "rrc.asn1"
 * 	`asn1c -fcompound-names -no-gen-example -gen-PER -pdu=RRCConnectionSetup -D src`
 */

#ifndef	_PhyLayerParameters_v9d0_H_
#define	_PhyLayerParameters_v9d0_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum PhyLayerParameters_v9d0__tm5_FDD_r9 {
	PhyLayerParameters_v9d0__tm5_FDD_r9_supported	= 0
} e_PhyLayerParameters_v9d0__tm5_FDD_r9;
typedef enum PhyLayerParameters_v9d0__tm5_TDD_r9 {
	PhyLayerParameters_v9d0__tm5_TDD_r9_supported	= 0
} e_PhyLayerParameters_v9d0__tm5_TDD_r9;

/* PhyLayerParameters-v9d0 */
typedef struct PhyLayerParameters_v9d0 {
	long	*tm5_FDD_r9	/* OPTIONAL */;
	long	*tm5_TDD_r9	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} PhyLayerParameters_v9d0_t;

/* Implementation */
/* extern asn_TYPE_descriptor_t asn_DEF_tm5_FDD_r9_2;	// (Use -fall-defs-global to expose) */
/* extern asn_TYPE_descriptor_t asn_DEF_tm5_TDD_r9_4;	// (Use -fall-defs-global to expose) */
extern asn_TYPE_descriptor_t asn_DEF_PhyLayerParameters_v9d0;
extern asn_SEQUENCE_specifics_t asn_SPC_PhyLayerParameters_v9d0_specs_1;
extern asn_TYPE_member_t asn_MBR_PhyLayerParameters_v9d0_1[2];

#ifdef __cplusplus
}
#endif

#endif	/* _PhyLayerParameters_v9d0_H_ */
#include <asn_internal.h>
