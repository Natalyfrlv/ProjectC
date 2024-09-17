/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "rrc.asn1"
 * 	`asn1c -fcompound-names -no-gen-example -gen-PER -pdu=RRCConnectionSetup -D src`
 */

#ifndef	_SL_GapConfig_r13_H_
#define	_SL_GapConfig_r13_H_


#include <asn_application.h>

/* Including external dependencies */
#include "SL-GapPatternList-r13.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* SL-GapConfig-r13 */
typedef struct SL_GapConfig_r13 {
	SL_GapPatternList_r13_t	 gapPatternList_r13;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} SL_GapConfig_r13_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_SL_GapConfig_r13;
extern asn_SEQUENCE_specifics_t asn_SPC_SL_GapConfig_r13_specs_1;
extern asn_TYPE_member_t asn_MBR_SL_GapConfig_r13_1[1];

#ifdef __cplusplus
}
#endif

#endif	/* _SL_GapConfig_r13_H_ */
#include <asn_internal.h>
