/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "rrc.asn1"
 * 	`asn1c -fcompound-names -no-gen-example -gen-PER -pdu=RRCConnectionSetup -D src`
 */

#ifndef	_LoggedMeasurementConfiguration_v1130_IEs_H_
#define	_LoggedMeasurementConfiguration_v1130_IEs_H_


#include <asn_application.h>

/* Including external dependencies */
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct PLMN_IdentityList3_r11;
struct AreaConfiguration_v1130;
struct LoggedMeasurementConfiguration_v1250_IEs;

/* LoggedMeasurementConfiguration-v1130-IEs */
typedef struct LoggedMeasurementConfiguration_v1130_IEs {
	struct PLMN_IdentityList3_r11	*plmn_IdentityList_r11	/* OPTIONAL */;
	struct AreaConfiguration_v1130	*areaConfiguration_v1130	/* OPTIONAL */;
	struct LoggedMeasurementConfiguration_v1250_IEs	*nonCriticalExtension	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} LoggedMeasurementConfiguration_v1130_IEs_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_LoggedMeasurementConfiguration_v1130_IEs;
extern asn_SEQUENCE_specifics_t asn_SPC_LoggedMeasurementConfiguration_v1130_IEs_specs_1;
extern asn_TYPE_member_t asn_MBR_LoggedMeasurementConfiguration_v1130_IEs_1[3];

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "PLMN-IdentityList3-r11.h"
#include "AreaConfiguration-v1130.h"
#include "LoggedMeasurementConfiguration-v1250-IEs.h"

#endif	/* _LoggedMeasurementConfiguration_v1130_IEs_H_ */
#include <asn_internal.h>
