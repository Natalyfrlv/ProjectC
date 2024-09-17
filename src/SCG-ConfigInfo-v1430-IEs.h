/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-InterNodeDefinitions"
 * 	found in "rrc.asn1"
 * 	`asn1c -fcompound-names -no-gen-example -gen-PER -pdu=RRCConnectionSetup -D src`
 */

#ifndef	_SCG_ConfigInfo_v1430_IEs_H_
#define	_SCG_ConfigInfo_v1430_IEs_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum SCG_ConfigInfo_v1430_IEs__makeBeforeBreakSCG_Req_r14 {
	SCG_ConfigInfo_v1430_IEs__makeBeforeBreakSCG_Req_r14_true	= 0
} e_SCG_ConfigInfo_v1430_IEs__makeBeforeBreakSCG_Req_r14;

/* Forward declarations */
struct MeasGapConfigPerCC_List_r14;
struct SCG_ConfigInfo_v1530_IEs;

/* SCG-ConfigInfo-v1430-IEs */
typedef struct SCG_ConfigInfo_v1430_IEs {
	long	*makeBeforeBreakSCG_Req_r14	/* OPTIONAL */;
	struct MeasGapConfigPerCC_List_r14	*measGapConfigPerCC_List	/* OPTIONAL */;
	struct SCG_ConfigInfo_v1530_IEs	*nonCriticalExtension	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} SCG_ConfigInfo_v1430_IEs_t;

/* Implementation */
/* extern asn_TYPE_descriptor_t asn_DEF_makeBeforeBreakSCG_Req_r14_2;	// (Use -fall-defs-global to expose) */
extern asn_TYPE_descriptor_t asn_DEF_SCG_ConfigInfo_v1430_IEs;
extern asn_SEQUENCE_specifics_t asn_SPC_SCG_ConfigInfo_v1430_IEs_specs_1;
extern asn_TYPE_member_t asn_MBR_SCG_ConfigInfo_v1430_IEs_1[3];

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "MeasGapConfigPerCC-List-r14.h"
#include "SCG-ConfigInfo-v1530-IEs.h"

#endif	/* _SCG_ConfigInfo_v1430_IEs_H_ */
#include <asn_internal.h>
