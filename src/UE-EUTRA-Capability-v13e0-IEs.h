/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "rrc.asn1"
 * 	`asn1c -fcompound-names -no-gen-example -gen-PER -pdu=RRCConnectionSetup -D src`
 */

#ifndef	_UE_EUTRA_Capability_v13e0_IEs_H_
#define	_UE_EUTRA_Capability_v13e0_IEs_H_


#include <asn_application.h>

/* Including external dependencies */
#include "PhyLayerParameters-v13e0.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* UE-EUTRA-Capability-v13e0-IEs */
typedef struct UE_EUTRA_Capability_v13e0_IEs {
	PhyLayerParameters_v13e0_t	 phyLayerParameters_v13e0;
	struct UE_EUTRA_Capability_v13e0_IEs__nonCriticalExtension {
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} *nonCriticalExtension;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} UE_EUTRA_Capability_v13e0_IEs_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_UE_EUTRA_Capability_v13e0_IEs;

#ifdef __cplusplus
}
#endif

#endif	/* _UE_EUTRA_Capability_v13e0_IEs_H_ */
#include <asn_internal.h>
