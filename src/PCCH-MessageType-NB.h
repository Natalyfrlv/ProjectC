/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "NBIOT-RRC-Definitions"
 * 	found in "rrc.asn1"
 * 	`asn1c -fcompound-names -no-gen-example -gen-PER -pdu=RRCConnectionSetup -D src`
 */

#ifndef	_PCCH_MessageType_NB_H_
#define	_PCCH_MessageType_NB_H_


#include <asn_application.h>

/* Including external dependencies */
#include "Paging-NB.h"
#include <constr_CHOICE.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum PCCH_MessageType_NB_PR {
	PCCH_MessageType_NB_PR_NOTHING,	/* No components present */
	PCCH_MessageType_NB_PR_c1,
	PCCH_MessageType_NB_PR_messageClassExtension
} PCCH_MessageType_NB_PR;
typedef enum PCCH_MessageType_NB__c1_PR {
	PCCH_MessageType_NB__c1_PR_NOTHING,	/* No components present */
	PCCH_MessageType_NB__c1_PR_paging_r13
} PCCH_MessageType_NB__c1_PR;

/* PCCH-MessageType-NB */
typedef struct PCCH_MessageType_NB {
	PCCH_MessageType_NB_PR present;
	union PCCH_MessageType_NB_u {
		struct PCCH_MessageType_NB__c1 {
			PCCH_MessageType_NB__c1_PR present;
			union PCCH_MessageType_NB__c1_u {
				Paging_NB_t	 paging_r13;
			} choice;
			
			/* Context for parsing across buffer boundaries */
			asn_struct_ctx_t _asn_ctx;
		} c1;
		struct PCCH_MessageType_NB__messageClassExtension {
			
			/* Context for parsing across buffer boundaries */
			asn_struct_ctx_t _asn_ctx;
		} messageClassExtension;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} PCCH_MessageType_NB_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_PCCH_MessageType_NB;
extern asn_CHOICE_specifics_t asn_SPC_PCCH_MessageType_NB_specs_1;
extern asn_TYPE_member_t asn_MBR_PCCH_MessageType_NB_1[2];
extern asn_per_constraints_t asn_PER_type_PCCH_MessageType_NB_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _PCCH_MessageType_NB_H_ */
#include <asn_internal.h>
