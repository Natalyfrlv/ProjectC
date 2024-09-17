/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "rrc.asn1"
 * 	`asn1c -fcompound-names -no-gen-example -gen-PER -pdu=RRCConnectionSetup -D src`
 */

#ifndef	_RRCConnectionRelease_v1530_IEs_H_
#define	_RRCConnectionRelease_v1530_IEs_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>
#include "NextHopChainingCount.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum RRCConnectionRelease_v1530_IEs__drb_ContinueROHC_r15 {
	RRCConnectionRelease_v1530_IEs__drb_ContinueROHC_r15_true	= 0
} e_RRCConnectionRelease_v1530_IEs__drb_ContinueROHC_r15;
typedef enum RRCConnectionRelease_v1530_IEs__cn_Type_r15 {
	RRCConnectionRelease_v1530_IEs__cn_Type_r15_epc	= 0,
	RRCConnectionRelease_v1530_IEs__cn_Type_r15_fivegc	= 1
} e_RRCConnectionRelease_v1530_IEs__cn_Type_r15;

/* Forward declarations */
struct MeasIdleConfigDedicated_r15;
struct RRC_InactiveConfig_r15;
struct RRCConnectionRelease_v1540_IEs;

/* RRCConnectionRelease-v1530-IEs */
typedef struct RRCConnectionRelease_v1530_IEs {
	long	*drb_ContinueROHC_r15	/* OPTIONAL */;
	NextHopChainingCount_t	*nextHopChainingCount_r15	/* OPTIONAL */;
	struct MeasIdleConfigDedicated_r15	*measIdleConfig_r15	/* OPTIONAL */;
	struct RRC_InactiveConfig_r15	*rrc_InactiveConfig_r15	/* OPTIONAL */;
	long	*cn_Type_r15	/* OPTIONAL */;
	struct RRCConnectionRelease_v1540_IEs	*nonCriticalExtension	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RRCConnectionRelease_v1530_IEs_t;

/* Implementation */
/* extern asn_TYPE_descriptor_t asn_DEF_drb_ContinueROHC_r15_2;	// (Use -fall-defs-global to expose) */
/* extern asn_TYPE_descriptor_t asn_DEF_cn_Type_r15_7;	// (Use -fall-defs-global to expose) */
extern asn_TYPE_descriptor_t asn_DEF_RRCConnectionRelease_v1530_IEs;
extern asn_SEQUENCE_specifics_t asn_SPC_RRCConnectionRelease_v1530_IEs_specs_1;
extern asn_TYPE_member_t asn_MBR_RRCConnectionRelease_v1530_IEs_1[6];

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "MeasIdleConfigDedicated-r15.h"
#include "RRC-InactiveConfig-r15.h"
#include "RRCConnectionRelease-v1540-IEs.h"

#endif	/* _RRCConnectionRelease_v1530_IEs_H_ */
#include <asn_internal.h>
