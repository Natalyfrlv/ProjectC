/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "rrc.asn1"
 * 	`asn1c -fcompound-names -no-gen-example -gen-PER -pdu=RRCConnectionSetup -D src`
 */

#ifndef	_UEAssistanceInformation_v1430_IEs_H_
#define	_UEAssistanceInformation_v1430_IEs_H_


#include <asn_application.h>

/* Including external dependencies */
#include <constr_SEQUENCE.h>
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum UEAssistanceInformation_v1430_IEs__rlm_Report_r14__rlm_Event_r14 {
	UEAssistanceInformation_v1430_IEs__rlm_Report_r14__rlm_Event_r14_earlyOutOfSync	= 0,
	UEAssistanceInformation_v1430_IEs__rlm_Report_r14__rlm_Event_r14_earlyInSync	= 1
} e_UEAssistanceInformation_v1430_IEs__rlm_Report_r14__rlm_Event_r14;
typedef enum UEAssistanceInformation_v1430_IEs__rlm_Report_r14__excessRep_MPDCCH_r14 {
	UEAssistanceInformation_v1430_IEs__rlm_Report_r14__excessRep_MPDCCH_r14_excessRep1	= 0,
	UEAssistanceInformation_v1430_IEs__rlm_Report_r14__excessRep_MPDCCH_r14_excessRep2	= 1
} e_UEAssistanceInformation_v1430_IEs__rlm_Report_r14__excessRep_MPDCCH_r14;

/* Forward declarations */
struct BW_Preference_r14;
struct DelayBudgetReport_r14;
struct UEAssistanceInformation_v1450_IEs;
struct TrafficPatternInfoList_r14;

/* UEAssistanceInformation-v1430-IEs */
typedef struct UEAssistanceInformation_v1430_IEs {
	struct BW_Preference_r14	*bw_Preference_r14	/* OPTIONAL */;
	struct UEAssistanceInformation_v1430_IEs__sps_AssistanceInformation_r14 {
		struct TrafficPatternInfoList_r14	*trafficPatternInfoListSL_r14	/* OPTIONAL */;
		struct TrafficPatternInfoList_r14	*trafficPatternInfoListUL_r14	/* OPTIONAL */;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} *sps_AssistanceInformation_r14;
	struct UEAssistanceInformation_v1430_IEs__rlm_Report_r14 {
		long	 rlm_Event_r14;
		long	*excessRep_MPDCCH_r14	/* OPTIONAL */;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} *rlm_Report_r14;
	struct DelayBudgetReport_r14	*delayBudgetReport_r14	/* OPTIONAL */;
	struct UEAssistanceInformation_v1450_IEs	*nonCriticalExtension	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} UEAssistanceInformation_v1430_IEs_t;

/* Implementation */
/* extern asn_TYPE_descriptor_t asn_DEF_rlm_Event_r14_7;	// (Use -fall-defs-global to expose) */
/* extern asn_TYPE_descriptor_t asn_DEF_excessRep_MPDCCH_r14_10;	// (Use -fall-defs-global to expose) */
extern asn_TYPE_descriptor_t asn_DEF_UEAssistanceInformation_v1430_IEs;
extern asn_SEQUENCE_specifics_t asn_SPC_UEAssistanceInformation_v1430_IEs_specs_1;
extern asn_TYPE_member_t asn_MBR_UEAssistanceInformation_v1430_IEs_1[5];

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "BW-Preference-r14.h"
#include "DelayBudgetReport-r14.h"
#include "UEAssistanceInformation-v1450-IEs.h"
#include "TrafficPatternInfoList-r14.h"

#endif	/* _UEAssistanceInformation_v1430_IEs_H_ */
#include <asn_internal.h>
