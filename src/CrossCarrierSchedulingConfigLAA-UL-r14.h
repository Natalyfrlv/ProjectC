/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "rrc.asn1"
 * 	`asn1c -fcompound-names -no-gen-example -gen-PER -pdu=RRCConnectionSetup -D src`
 */

#ifndef	_CrossCarrierSchedulingConfigLAA_UL_r14_H_
#define	_CrossCarrierSchedulingConfigLAA_UL_r14_H_


#include <asn_application.h>

/* Including external dependencies */
#include "ServCellIndex-r13.h"
#include <NativeInteger.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* CrossCarrierSchedulingConfigLAA-UL-r14 */
typedef struct CrossCarrierSchedulingConfigLAA_UL_r14 {
	ServCellIndex_r13_t	 schedulingCellId_r14;
	long	 cif_InSchedulingCell_r14;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} CrossCarrierSchedulingConfigLAA_UL_r14_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_CrossCarrierSchedulingConfigLAA_UL_r14;
extern asn_SEQUENCE_specifics_t asn_SPC_CrossCarrierSchedulingConfigLAA_UL_r14_specs_1;
extern asn_TYPE_member_t asn_MBR_CrossCarrierSchedulingConfigLAA_UL_r14_1[2];

#ifdef __cplusplus
}
#endif

#endif	/* _CrossCarrierSchedulingConfigLAA_UL_r14_H_ */
#include <asn_internal.h>
