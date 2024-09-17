/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "rrc.asn1"
 * 	`asn1c -fcompound-names -no-gen-example -gen-PER -pdu=RRCConnectionSetup -D src`
 */

#ifndef	_SL_GapRequest_r13_H_
#define	_SL_GapRequest_r13_H_


#include <asn_application.h>

/* Including external dependencies */
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct SL_GapFreqInfo_r13;

/* SL-GapRequest-r13 */
typedef struct SL_GapRequest_r13 {
	A_SEQUENCE_OF(struct SL_GapFreqInfo_r13) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} SL_GapRequest_r13_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_SL_GapRequest_r13;
extern asn_SET_OF_specifics_t asn_SPC_SL_GapRequest_r13_specs_1;
extern asn_TYPE_member_t asn_MBR_SL_GapRequest_r13_1[1];
extern asn_per_constraints_t asn_PER_type_SL_GapRequest_r13_constr_1;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "SL-GapFreqInfo-r13.h"

#endif	/* _SL_GapRequest_r13_H_ */
#include <asn_internal.h>
