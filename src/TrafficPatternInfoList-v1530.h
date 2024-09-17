/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "rrc.asn1"
 * 	`asn1c -fcompound-names -no-gen-example -gen-PER -pdu=RRCConnectionSetup -D src`
 */

#ifndef	_TrafficPatternInfoList_v1530_H_
#define	_TrafficPatternInfoList_v1530_H_


#include <asn_application.h>

/* Including external dependencies */
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct TrafficPatternInfo_v1530;

/* TrafficPatternInfoList-v1530 */
typedef struct TrafficPatternInfoList_v1530 {
	A_SEQUENCE_OF(struct TrafficPatternInfo_v1530) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} TrafficPatternInfoList_v1530_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_TrafficPatternInfoList_v1530;
extern asn_SET_OF_specifics_t asn_SPC_TrafficPatternInfoList_v1530_specs_1;
extern asn_TYPE_member_t asn_MBR_TrafficPatternInfoList_v1530_1[1];
extern asn_per_constraints_t asn_PER_type_TrafficPatternInfoList_v1530_constr_1;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "TrafficPatternInfo-v1530.h"

#endif	/* _TrafficPatternInfoList_v1530_H_ */
#include <asn_internal.h>
