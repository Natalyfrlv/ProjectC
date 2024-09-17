/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "rrc.asn1"
 * 	`asn1c -fcompound-names -no-gen-example -gen-PER -pdu=RRCConnectionSetup -D src`
 */

#ifndef	_PDCP_Parameters_v1530_H_
#define	_PDCP_Parameters_v1530_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum PDCP_Parameters_v1530__pdcp_Duplication_r15 {
	PDCP_Parameters_v1530__pdcp_Duplication_r15_supported	= 0
} e_PDCP_Parameters_v1530__pdcp_Duplication_r15;

/* Forward declarations */
struct SupportedUDC_r15;

/* PDCP-Parameters-v1530 */
typedef struct PDCP_Parameters_v1530 {
	struct SupportedUDC_r15	*supportedUDC_r15	/* OPTIONAL */;
	long	*pdcp_Duplication_r15	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} PDCP_Parameters_v1530_t;

/* Implementation */
/* extern asn_TYPE_descriptor_t asn_DEF_pdcp_Duplication_r15_3;	// (Use -fall-defs-global to expose) */
extern asn_TYPE_descriptor_t asn_DEF_PDCP_Parameters_v1530;
extern asn_SEQUENCE_specifics_t asn_SPC_PDCP_Parameters_v1530_specs_1;
extern asn_TYPE_member_t asn_MBR_PDCP_Parameters_v1530_1[2];

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "SupportedUDC-r15.h"

#endif	/* _PDCP_Parameters_v1530_H_ */
#include <asn_internal.h>
