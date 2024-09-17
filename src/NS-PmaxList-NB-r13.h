/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "NBIOT-RRC-Definitions"
 * 	found in "rrc.asn1"
 * 	`asn1c -fcompound-names -no-gen-example -gen-PER -pdu=RRCConnectionSetup -D src`
 */

#ifndef	_NS_PmaxList_NB_r13_H_
#define	_NS_PmaxList_NB_r13_H_


#include <asn_application.h>

/* Including external dependencies */
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct NS_PmaxValue_NB_r13;

/* NS-PmaxList-NB-r13 */
typedef struct NS_PmaxList_NB_r13 {
	A_SEQUENCE_OF(struct NS_PmaxValue_NB_r13) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} NS_PmaxList_NB_r13_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_NS_PmaxList_NB_r13;
extern asn_SET_OF_specifics_t asn_SPC_NS_PmaxList_NB_r13_specs_1;
extern asn_TYPE_member_t asn_MBR_NS_PmaxList_NB_r13_1[1];
extern asn_per_constraints_t asn_PER_type_NS_PmaxList_NB_r13_constr_1;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "NS-PmaxValue-NB-r13.h"

#endif	/* _NS_PmaxList_NB_r13_H_ */
#include <asn_internal.h>
