/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "NBIOT-RRC-Definitions"
 * 	found in "rrc.asn1"
 * 	`asn1c -fcompound-names -no-gen-example -gen-PER -pdu=RRCConnectionSetup -D src`
 */

#ifndef	_RRCConnectionSetupComplete_NB_H_
#define	_RRCConnectionSetupComplete_NB_H_


#include <asn_application.h>

/* Including external dependencies */
#include "RRC-TransactionIdentifier.h"
#include "RRCConnectionSetupComplete-NB-r13-IEs.h"
#include <constr_SEQUENCE.h>
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum RRCConnectionSetupComplete_NB__criticalExtensions_PR {
	RRCConnectionSetupComplete_NB__criticalExtensions_PR_NOTHING,	/* No components present */
	RRCConnectionSetupComplete_NB__criticalExtensions_PR_rrcConnectionSetupComplete_r13,
	RRCConnectionSetupComplete_NB__criticalExtensions_PR_criticalExtensionsFuture
} RRCConnectionSetupComplete_NB__criticalExtensions_PR;

/* RRCConnectionSetupComplete-NB */
typedef struct RRCConnectionSetupComplete_NB {
	RRC_TransactionIdentifier_t	 rrc_TransactionIdentifier;
	struct RRCConnectionSetupComplete_NB__criticalExtensions {
		RRCConnectionSetupComplete_NB__criticalExtensions_PR present;
		union RRCConnectionSetupComplete_NB__criticalExtensions_u {
			RRCConnectionSetupComplete_NB_r13_IEs_t	 rrcConnectionSetupComplete_r13;
			struct RRCConnectionSetupComplete_NB__criticalExtensions__criticalExtensionsFuture {
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} criticalExtensionsFuture;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} criticalExtensions;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RRCConnectionSetupComplete_NB_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RRCConnectionSetupComplete_NB;
extern asn_SEQUENCE_specifics_t asn_SPC_RRCConnectionSetupComplete_NB_specs_1;
extern asn_TYPE_member_t asn_MBR_RRCConnectionSetupComplete_NB_1[2];

#ifdef __cplusplus
}
#endif

#endif	/* _RRCConnectionSetupComplete_NB_H_ */
#include <asn_internal.h>
