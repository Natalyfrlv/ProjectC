/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "rrc.asn1"
 * 	`asn1c -fcompound-names -no-gen-example -gen-PER -pdu=RRCConnectionSetup -D src`
 */

#ifndef	_UAC_BarringPerCat_r15_H_
#define	_UAC_BarringPerCat_r15_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeInteger.h>
#include "UAC-BarringInfoSetIndex-r15.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* UAC-BarringPerCat-r15 */
typedef struct UAC_BarringPerCat_r15 {
	long	 accessCategory_r15;
	UAC_BarringInfoSetIndex_r15_t	 uac_barringInfoSetIndex_r15;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} UAC_BarringPerCat_r15_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_UAC_BarringPerCat_r15;
extern asn_SEQUENCE_specifics_t asn_SPC_UAC_BarringPerCat_r15_specs_1;
extern asn_TYPE_member_t asn_MBR_UAC_BarringPerCat_r15_1[2];

#ifdef __cplusplus
}
#endif

#endif	/* _UAC_BarringPerCat_r15_H_ */
#include <asn_internal.h>
