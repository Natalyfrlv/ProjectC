/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "NBIOT-RRC-Definitions"
 * 	found in "rrc.asn1"
 * 	`asn1c -fcompound-names -no-gen-example -gen-PER -pdu=RRCConnectionSetup -D src`
 */

#ifndef	_SystemInformationBlockType15_NB_r14_H_
#define	_SystemInformationBlockType15_NB_r14_H_


#include <asn_application.h>

/* Including external dependencies */
#include <OCTET_STRING.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct MBMS_SAI_List_r11;
struct MBMS_SAI_InterFreqList_NB_r14;

/* SystemInformationBlockType15-NB-r14 */
typedef struct SystemInformationBlockType15_NB_r14 {
	struct MBMS_SAI_List_r11	*mbms_SAI_IntraFreq_r14	/* OPTIONAL */;
	struct MBMS_SAI_InterFreqList_NB_r14	*mbms_SAI_InterFreqList_r14	/* OPTIONAL */;
	OCTET_STRING_t	*lateNonCriticalExtension	/* OPTIONAL */;
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} SystemInformationBlockType15_NB_r14_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_SystemInformationBlockType15_NB_r14;
extern asn_SEQUENCE_specifics_t asn_SPC_SystemInformationBlockType15_NB_r14_specs_1;
extern asn_TYPE_member_t asn_MBR_SystemInformationBlockType15_NB_r14_1[3];

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "MBMS-SAI-List-r11.h"
#include "MBMS-SAI-InterFreqList-NB-r14.h"

#endif	/* _SystemInformationBlockType15_NB_r14_H_ */
#include <asn_internal.h>
