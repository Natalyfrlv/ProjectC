/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "rrc.asn1"
 * 	`asn1c -fcompound-names -no-gen-example -gen-PER -pdu=RRCConnectionSetup -D src`
 */

#ifndef	_RRCConnectionResumeRequest_r13_H_
#define	_RRCConnectionResumeRequest_r13_H_


#include <asn_application.h>

/* Including external dependencies */
#include "RRCConnectionResumeRequest-r13-IEs.h"
#include "RRCConnectionResumeRequest-5GC-r15-IEs.h"
#include <constr_CHOICE.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum RRCConnectionResumeRequest_r13__criticalExtensions_PR {
	RRCConnectionResumeRequest_r13__criticalExtensions_PR_NOTHING,	/* No components present */
	RRCConnectionResumeRequest_r13__criticalExtensions_PR_rrcConnectionResumeRequest_r13,
	RRCConnectionResumeRequest_r13__criticalExtensions_PR_rrcConnectionResumeRequest_r15
} RRCConnectionResumeRequest_r13__criticalExtensions_PR;

/* RRCConnectionResumeRequest-r13 */
typedef struct RRCConnectionResumeRequest_r13 {
	struct RRCConnectionResumeRequest_r13__criticalExtensions {
		RRCConnectionResumeRequest_r13__criticalExtensions_PR present;
		union RRCConnectionResumeRequest_r13__criticalExtensions_u {
			RRCConnectionResumeRequest_r13_IEs_t	 rrcConnectionResumeRequest_r13;
			RRCConnectionResumeRequest_5GC_r15_IEs_t	 rrcConnectionResumeRequest_r15;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} criticalExtensions;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RRCConnectionResumeRequest_r13_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RRCConnectionResumeRequest_r13;
extern asn_SEQUENCE_specifics_t asn_SPC_RRCConnectionResumeRequest_r13_specs_1;
extern asn_TYPE_member_t asn_MBR_RRCConnectionResumeRequest_r13_1[1];

#ifdef __cplusplus
}
#endif

#endif	/* _RRCConnectionResumeRequest_r13_H_ */
#include <asn_internal.h>
