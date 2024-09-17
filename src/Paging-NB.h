/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "NBIOT-RRC-Definitions"
 * 	found in "rrc.asn1"
 * 	`asn1c -fcompound-names -no-gen-example -gen-PER -pdu=RRCConnectionSetup -D src`
 */

#ifndef	_Paging_NB_H_
#define	_Paging_NB_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum Paging_NB__systemInfoModification_r13 {
	Paging_NB__systemInfoModification_r13_true	= 0
} e_Paging_NB__systemInfoModification_r13;
typedef enum Paging_NB__systemInfoModification_eDRX_r13 {
	Paging_NB__systemInfoModification_eDRX_r13_true	= 0
} e_Paging_NB__systemInfoModification_eDRX_r13;

/* Forward declarations */
struct PagingRecordList_NB_r13;

/* Paging-NB */
typedef struct Paging_NB {
	struct PagingRecordList_NB_r13	*pagingRecordList_r13	/* OPTIONAL */;
	long	*systemInfoModification_r13	/* OPTIONAL */;
	long	*systemInfoModification_eDRX_r13	/* OPTIONAL */;
	struct Paging_NB__nonCriticalExtension {
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} *nonCriticalExtension;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Paging_NB_t;

/* Implementation */
/* extern asn_TYPE_descriptor_t asn_DEF_systemInfoModification_r13_3;	// (Use -fall-defs-global to expose) */
/* extern asn_TYPE_descriptor_t asn_DEF_systemInfoModification_eDRX_r13_5;	// (Use -fall-defs-global to expose) */
extern asn_TYPE_descriptor_t asn_DEF_Paging_NB;
extern asn_SEQUENCE_specifics_t asn_SPC_Paging_NB_specs_1;
extern asn_TYPE_member_t asn_MBR_Paging_NB_1[4];

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "PagingRecordList-NB-r13.h"

#endif	/* _Paging_NB_H_ */
#include <asn_internal.h>
