/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "NBIOT-RRC-Definitions"
 * 	found in "rrc.asn1"
 * 	`asn1c -fcompound-names -no-gen-example -gen-PER -pdu=RRCConnectionSetup -D src`
 */

#ifndef	_AB_Config_NB_r13_H_
#define	_AB_Config_NB_r13_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>
#include <BIT_STRING.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum AB_Config_NB_r13__ab_Category_r13 {
	AB_Config_NB_r13__ab_Category_r13_a	= 0,
	AB_Config_NB_r13__ab_Category_r13_b	= 1,
	AB_Config_NB_r13__ab_Category_r13_c	= 2
} e_AB_Config_NB_r13__ab_Category_r13;
typedef enum AB_Config_NB_r13__ab_BarringForExceptionData_r13 {
	AB_Config_NB_r13__ab_BarringForExceptionData_r13_true	= 0
} e_AB_Config_NB_r13__ab_BarringForExceptionData_r13;

/* AB-Config-NB-r13 */
typedef struct AB_Config_NB_r13 {
	long	 ab_Category_r13;
	BIT_STRING_t	 ab_BarringBitmap_r13;
	long	*ab_BarringForExceptionData_r13	/* OPTIONAL */;
	BIT_STRING_t	 ab_BarringForSpecialAC_r13;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} AB_Config_NB_r13_t;

/* Implementation */
/* extern asn_TYPE_descriptor_t asn_DEF_ab_Category_r13_2;	// (Use -fall-defs-global to expose) */
/* extern asn_TYPE_descriptor_t asn_DEF_ab_BarringForExceptionData_r13_7;	// (Use -fall-defs-global to expose) */
extern asn_TYPE_descriptor_t asn_DEF_AB_Config_NB_r13;
extern asn_SEQUENCE_specifics_t asn_SPC_AB_Config_NB_r13_specs_1;
extern asn_TYPE_member_t asn_MBR_AB_Config_NB_r13_1[4];

#ifdef __cplusplus
}
#endif

#endif	/* _AB_Config_NB_r13_H_ */
#include <asn_internal.h>
