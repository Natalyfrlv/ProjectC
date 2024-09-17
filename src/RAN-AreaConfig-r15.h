/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "rrc.asn1"
 * 	`asn1c -fcompound-names -no-gen-example -gen-PER -pdu=RRCConnectionSetup -D src`
 */

#ifndef	_RAN_AreaConfig_r15_H_
#define	_RAN_AreaConfig_r15_H_


#include <asn_application.h>

/* Including external dependencies */
#include "TrackingAreaCode-5GC-r15.h"
#include "RAN-AreaCode-r15.h"
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* RAN-AreaConfig-r15 */
typedef struct RAN_AreaConfig_r15 {
	TrackingAreaCode_5GC_r15_t	 trackingAreaCode_5GC_r15;
	struct RAN_AreaConfig_r15__ran_AreaCodeList_r15 {
		A_SEQUENCE_OF(RAN_AreaCode_r15_t) list;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} *ran_AreaCodeList_r15;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RAN_AreaConfig_r15_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RAN_AreaConfig_r15;
extern asn_SEQUENCE_specifics_t asn_SPC_RAN_AreaConfig_r15_specs_1;
extern asn_TYPE_member_t asn_MBR_RAN_AreaConfig_r15_1[2];

#ifdef __cplusplus
}
#endif

#endif	/* _RAN_AreaConfig_r15_H_ */
#include <asn_internal.h>
