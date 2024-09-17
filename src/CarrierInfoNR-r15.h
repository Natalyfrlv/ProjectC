/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "rrc.asn1"
 * 	`asn1c -fcompound-names -no-gen-example -gen-PER -pdu=RRCConnectionSetup -D src`
 */

#ifndef	_CarrierInfoNR_r15_H_
#define	_CarrierInfoNR_r15_H_


#include <asn_application.h>

/* Including external dependencies */
#include "ARFCN-ValueNR-r15.h"
#include <NativeEnumerated.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum CarrierInfoNR_r15__subcarrierSpacingSSB_r15 {
	CarrierInfoNR_r15__subcarrierSpacingSSB_r15_kHz15	= 0,
	CarrierInfoNR_r15__subcarrierSpacingSSB_r15_kHz30	= 1,
	CarrierInfoNR_r15__subcarrierSpacingSSB_r15_kHz120	= 2,
	CarrierInfoNR_r15__subcarrierSpacingSSB_r15_kHz240	= 3
} e_CarrierInfoNR_r15__subcarrierSpacingSSB_r15;

/* Forward declarations */
struct MTC_SSB_NR_r15;

/* CarrierInfoNR-r15 */
typedef struct CarrierInfoNR_r15 {
	ARFCN_ValueNR_r15_t	 carrierFreq_r15;
	long	 subcarrierSpacingSSB_r15;
	struct MTC_SSB_NR_r15	*smtc_r15	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} CarrierInfoNR_r15_t;

/* Implementation */
/* extern asn_TYPE_descriptor_t asn_DEF_subcarrierSpacingSSB_r15_3;	// (Use -fall-defs-global to expose) */
extern asn_TYPE_descriptor_t asn_DEF_CarrierInfoNR_r15;
extern asn_SEQUENCE_specifics_t asn_SPC_CarrierInfoNR_r15_specs_1;
extern asn_TYPE_member_t asn_MBR_CarrierInfoNR_r15_1[3];

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "MTC-SSB-NR-r15.h"

#endif	/* _CarrierInfoNR_r15_H_ */
#include <asn_internal.h>
