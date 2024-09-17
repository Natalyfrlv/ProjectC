/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "rrc.asn1"
 * 	`asn1c -fcompound-names -no-gen-example -gen-PER -pdu=RRCConnectionSetup -D src`
 */

#ifndef	_MeasObjectGERAN_H_
#define	_MeasObjectGERAN_H_


#include <asn_application.h>

/* Including external dependencies */
#include "CarrierFreqsGERAN.h"
#include "Q-OffsetRangeInterRAT.h"
#include <BIT_STRING.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct PhysCellIdGERAN;

/* MeasObjectGERAN */
typedef struct MeasObjectGERAN {
	CarrierFreqsGERAN_t	 carrierFreqs;
	Q_OffsetRangeInterRAT_t	 offsetFreq	/* DEFAULT 0 */;
	BIT_STRING_t	*ncc_Permitted	/* DEFAULT 'FF'HH */;
	struct PhysCellIdGERAN	*cellForWhichToReportCGI	/* OPTIONAL */;
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} MeasObjectGERAN_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_MeasObjectGERAN;
extern asn_SEQUENCE_specifics_t asn_SPC_MeasObjectGERAN_specs_1;
extern asn_TYPE_member_t asn_MBR_MeasObjectGERAN_1[4];

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "PhysCellIdGERAN.h"

#endif	/* _MeasObjectGERAN_H_ */
#include <asn_internal.h>
