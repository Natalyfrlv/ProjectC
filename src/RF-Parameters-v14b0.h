/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "rrc.asn1"
 * 	`asn1c -fcompound-names -no-gen-example -gen-PER -pdu=RRCConnectionSetup -D src`
 */

#ifndef	_RF_Parameters_v14b0_H_
#define	_RF_Parameters_v14b0_H_


#include <asn_application.h>

/* Including external dependencies */
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct SupportedBandCombination_v14b0;
struct SupportedBandCombinationAdd_v14b0;
struct SupportedBandCombinationReduced_v14b0;

/* RF-Parameters-v14b0 */
typedef struct RF_Parameters_v14b0 {
	struct SupportedBandCombination_v14b0	*supportedBandCombination_v14b0	/* OPTIONAL */;
	struct SupportedBandCombinationAdd_v14b0	*supportedBandCombinationAdd_v14b0	/* OPTIONAL */;
	struct SupportedBandCombinationReduced_v14b0	*supportedBandCombinationReduced_v14b0	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RF_Parameters_v14b0_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RF_Parameters_v14b0;
extern asn_SEQUENCE_specifics_t asn_SPC_RF_Parameters_v14b0_specs_1;
extern asn_TYPE_member_t asn_MBR_RF_Parameters_v14b0_1[3];

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "SupportedBandCombination-v14b0.h"
#include "SupportedBandCombinationAdd-v14b0.h"
#include "SupportedBandCombinationReduced-v14b0.h"

#endif	/* _RF_Parameters_v14b0_H_ */
#include <asn_internal.h>
