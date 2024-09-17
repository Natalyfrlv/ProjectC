/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "rrc.asn1"
 * 	`asn1c -fcompound-names -no-gen-example -gen-PER -pdu=RRCConnectionSetup -D src`
 */

#ifndef	_LoggedMeasurementConfiguration_v1530_IEs_H_
#define	_LoggedMeasurementConfiguration_v1530_IEs_H_


#include <asn_application.h>

/* Including external dependencies */
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct BT_NameList_r15;
struct WLAN_NameList_r15;

/* LoggedMeasurementConfiguration-v1530-IEs */
typedef struct LoggedMeasurementConfiguration_v1530_IEs {
	struct BT_NameList_r15	*bt_NameList_r15	/* OPTIONAL */;
	struct WLAN_NameList_r15	*wlan_NameList_r15	/* OPTIONAL */;
	struct LoggedMeasurementConfiguration_v1530_IEs__nonCriticalExtension {
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} *nonCriticalExtension;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} LoggedMeasurementConfiguration_v1530_IEs_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_LoggedMeasurementConfiguration_v1530_IEs;
extern asn_SEQUENCE_specifics_t asn_SPC_LoggedMeasurementConfiguration_v1530_IEs_specs_1;
extern asn_TYPE_member_t asn_MBR_LoggedMeasurementConfiguration_v1530_IEs_1[3];

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "BT-NameList-r15.h"
#include "WLAN-NameList-r15.h"

#endif	/* _LoggedMeasurementConfiguration_v1530_IEs_H_ */
#include <asn_internal.h>
