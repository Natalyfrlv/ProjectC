/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "rrc.asn1"
 * 	`asn1c -fcompound-names -no-gen-example -gen-PER -pdu=RRCConnectionSetup -D src`
 */

#ifndef	_SCellToAddModList_v13c0_H_
#define	_SCellToAddModList_v13c0_H_


#include <asn_application.h>

/* Including external dependencies */
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct SCellToAddMod_v13c0;

/* SCellToAddModList-v13c0 */
typedef struct SCellToAddModList_v13c0 {
	A_SEQUENCE_OF(struct SCellToAddMod_v13c0) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} SCellToAddModList_v13c0_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_SCellToAddModList_v13c0;
extern asn_SET_OF_specifics_t asn_SPC_SCellToAddModList_v13c0_specs_1;
extern asn_TYPE_member_t asn_MBR_SCellToAddModList_v13c0_1[1];
extern asn_per_constraints_t asn_PER_type_SCellToAddModList_v13c0_constr_1;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "SCellToAddMod-v13c0.h"

#endif	/* _SCellToAddModList_v13c0_H_ */
#include <asn_internal.h>
