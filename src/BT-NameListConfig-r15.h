/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "rrc.asn1"
 * 	`asn1c -fcompound-names -no-gen-example -gen-PER -pdu=RRCConnectionSetup -D src`
 */

#ifndef	_BT_NameListConfig_r15_H_
#define	_BT_NameListConfig_r15_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NULL.h>
#include "BT-NameList-r15.h"
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum BT_NameListConfig_r15_PR {
	BT_NameListConfig_r15_PR_NOTHING,	/* No components present */
	BT_NameListConfig_r15_PR_release,
	BT_NameListConfig_r15_PR_setup
} BT_NameListConfig_r15_PR;

/* BT-NameListConfig-r15 */
typedef struct BT_NameListConfig_r15 {
	BT_NameListConfig_r15_PR present;
	union BT_NameListConfig_r15_u {
		NULL_t	 release;
		BT_NameList_r15_t	 setup;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} BT_NameListConfig_r15_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_BT_NameListConfig_r15;
extern asn_CHOICE_specifics_t asn_SPC_BT_NameListConfig_r15_specs_1;
extern asn_TYPE_member_t asn_MBR_BT_NameListConfig_r15_1[2];
extern asn_per_constraints_t asn_PER_type_BT_NameListConfig_r15_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _BT_NameListConfig_r15_H_ */
#include <asn_internal.h>
