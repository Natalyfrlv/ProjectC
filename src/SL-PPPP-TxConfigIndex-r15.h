/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "rrc.asn1"
 * 	`asn1c -fcompound-names -no-gen-example -gen-PER -pdu=RRCConnectionSetup -D src`
 */

#ifndef	_SL_PPPP_TxConfigIndex_r15_H_
#define	_SL_PPPP_TxConfigIndex_r15_H_


#include <asn_application.h>

/* Including external dependencies */
#include "SL-Priority-r13.h"
#include <NativeInteger.h>
#include "Tx-ConfigIndex-r14.h"
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct MCS_PSSCH_Range_r15;

/* SL-PPPP-TxConfigIndex-r15 */
typedef struct SL_PPPP_TxConfigIndex_r15 {
	SL_Priority_r13_t	 priorityThreshold_r15;
	long	 defaultTxConfigIndex_r15;
	long	 cbr_ConfigIndex_r15;
	struct SL_PPPP_TxConfigIndex_r15__tx_ConfigIndexList_r15 {
		A_SEQUENCE_OF(Tx_ConfigIndex_r14_t) list;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} tx_ConfigIndexList_r15;
	struct SL_PPPP_TxConfigIndex_r15__mcs_PSSCH_RangeList_r15 {
		A_SEQUENCE_OF(struct MCS_PSSCH_Range_r15) list;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} mcs_PSSCH_RangeList_r15;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} SL_PPPP_TxConfigIndex_r15_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_SL_PPPP_TxConfigIndex_r15;
extern asn_SEQUENCE_specifics_t asn_SPC_SL_PPPP_TxConfigIndex_r15_specs_1;
extern asn_TYPE_member_t asn_MBR_SL_PPPP_TxConfigIndex_r15_1[5];

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "MCS-PSSCH-Range-r15.h"

#endif	/* _SL_PPPP_TxConfigIndex_r15_H_ */
#include <asn_internal.h>
